"""Локальный HTML, внешний CSS и переход на HTTPS-страницу в гостевой MyOS."""
import pathlib, tempfile, time, subprocess, threading, ssl, http.server
from disk_install_smoke import VM,run
from hardware_inventory_smoke import login

B=pathlib.Path('build')

def main():
    with tempfile.TemporaryDirectory(prefix='myos-netsurf-') as directory:
        temp=pathlib.Path(directory);root=temp/'root.img'
        class Fixture(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def do_GET(self):
                if self.path == '/next':
                    mime = 'text/html'
                    body = (b'<!doctype html><body><script>document.write('
                            b'\'<div style="background:#2e679b;height:80px">HTTPS and JS</div>\''
                            b');</script></body>')
                elif self.path == '/test.css':
                    mime, body = 'text/css', b'h1 {background-color:#ad42ce}'
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = http.server.ThreadingHTTPServer(('127.0.0.1',0), Fixture)
        key, certificate = temp/'key.pem', temp/'test-ca.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
                        '-subj','/CN=NetSurf smoke','-addext','subjectAltName=IP:10.0.2.2',
                        '-keyout',str(key),'-out',str(certificate)],check=True,stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate,key)
        server.socket = context.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        with root.open('wb') as f:f.truncate(64*1048576)
        for d in ['/bin','/lib','/lib/fonts','/etc','/root','/tmp','/ext','/ext/instructions','/ext/instructions/netsurf','/etc/ssl']:run(B/'myfs',root,'mkdir',d)
        for name in ['sh','desktop','ext','tar','sleep']:
            run(B/'myfs',root,'put',B/'user'/name,'/bin/'+name)
        for name,source in [('ld.so',B/'ld.so'),('libc.so',B/'user/libc.so'),('libgfx.so',B/'user/libgfx.so')]:
            run(B/'myfs',root,'put',source,'/lib/'+name)
        for font in pathlib.Path('fonts').glob('*.ttf'):run(B/'myfs',root,'put',font,'/lib/fonts/'+font.name)
        preference=temp/'display';preference.write_text('1024x768\ncursor=sw\n')
        run(B/'myfs',root,'put',preference,'/etc/display')
        run(B/'myfs',root,'put',B/'netsurf.tar.gz','/ext/instructions/netsurf/netsurf.tar.gz')
        run(B/'myfs',root,'put','ext/instructions/netsurf/install.recipe','/ext/instructions/netsurf/setup.inst')
        run(B/'myfs',root,'put',certificate,'/etc/ssl/cert.pem')
        page=temp/'page.html'
        origin = f'https://10.0.2.2:{server.server_port}'
        page.write_text(f'<!doctype html><link rel=stylesheet href="{origin}/test.css">'
                        f'<body style="background:#12ab34"><a href="{origin}/next"><h1>Open HTTPS</h1></a></body>')
        run(B/'myfs',root,'put',page,'/tmp/page.html')
        script=temp/'ns.sh'
        script.write_text('ext install netsurf\ndesktop &\nsleep 2\necho starting browser\n/ext/bin/netsurf -v file:///tmp/page.html\n')
        run(B/'myfs',root,'put',script,'/tmp/ns.sh')
        vm=VM('netsurf-https',['-drive',f'format=raw,file={B}/os.img,index=0,snapshot=on','-drive',f'format=raw,file={root},index=1','-netdev','user,id=ns','-device','e1000,netdev=ns'],memory='512M')
        try:
            login(vm)
            vm.send('sh /tmp/ns.sh','starting browser')
            vm.wait('calling browser_window_create',timeout=300)
            clicked = False
            for attempt in range(180):
                shot=temp/'frame.ppm'
                vm.qmp('screendump',{'filename':str(shot)})
                pixels = shot.read_bytes()
                link = bytes([0xad,0x42,0xce])*300
                if not clicked and bytes([0x12,0xab,0x34])*400 in pixels and link in pixels:
                    header, dimensions, maximum, raster = pixels.split(b'\n', 3)
                    width = int(dimensions.split()[0])
                    first = raster.index(link) // 3
                    x, y = first % width + 15, first // width + 10
                    def monitor(command):
                        vm.qmp('human-monitor-command', {'command-line': command})
                        time.sleep(.05)
                    for _ in range(14):
                        monitor('mouse_move -100 -100')
                    while x or y:
                        dx, dy = min(100,x), min(100,y)
                        monitor(f'mouse_move {dx} {dy}')
                        x, y = x-dx, y-dy
                    monitor('mouse_button 1')
                    monitor('mouse_button 0')
                    clicked = True
                if clicked and bytes([0x2e,0x67,0x9b])*400 in pixels:
                    print('NetSurf port: local HTML, HTTPS CSS, link navigation and JavaScript: PASS')
                    return
                time.sleep(.3)
            raise AssertionError('window pixels missing')
        finally:
            vm.stop()
            server.shutdown()
            server.server_close()
main()
