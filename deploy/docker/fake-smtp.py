import socketserver
from pathlib import Path
from datetime import datetime
from email import policy
from email.parser import BytesParser

out = Path("smtp-captures")
out.mkdir(exist_ok=True)

class SMTPHandler(socketserver.StreamRequestHandler):
    def send(self, line):
        self.wfile.write((line + "\r\n").encode())
        self.wfile.flush()

    def handle(self):
        mail_from = None
        rcpt_tos = []
        self.send("220 fake-smtp-capture ready")

        while True:
            line = self.rfile.readline().decode(errors="replace").rstrip("\r\n")
            if not line:
                return
            upper = line.upper()

            if upper.startswith("EHLO") or upper.startswith("HELO"):
                self.send("250-fake-smtp-capture")
                self.send("250 SIZE 104857600")
            elif upper.startswith("MAIL FROM:"):
                mail_from = line.split(":", 1)[1].strip("<> ")
                self.send("250 OK")
            elif upper.startswith("RCPT TO:"):
                rcpt_tos.append(line.split(":", 1)[1].strip("<> "))
                self.send("250 OK")
            elif upper == "DATA":
                self.send("354 End data with <CR><LF>.<CR><LF>")
                data = []
                while True:
                    raw = self.rfile.readline()
                    if raw in (b".\r\n", b".\n", b"."):
                        break
                    data.append(raw)
                content = b"".join(data)

                ts = datetime.now().strftime("%Y%m%d-%H%M%S")
                path = out / f"{ts}.eml"
                path.write_bytes(content)

                msg = BytesParser(policy=policy.default).parsebytes(content)
                print("\n--- captured message ---", flush=True)
                print("MAIL FROM:", mail_from, flush=True)
                print("RCPT TO:", rcpt_tos, flush=True)
                print("To:", msg.get("To"), flush=True)
                print("Cc:", msg.get("Cc"), flush=True)
                print("Bcc:", msg.get("Bcc"), flush=True)
                print("Saved:", path, flush=True)

                self.send("250 OK")
            elif upper == "RSET":
                mail_from = None
                rcpt_tos = []
                self.send("250 OK")
            elif upper == "QUIT":
                self.send("221 Bye")
                return
            else:
                self.send("250 OK")

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

with Server(("0.0.0.0", 1025), SMTPHandler) as server:
    print("Fake SMTP capture listening on 0.0.0.0:1025", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping fake SMTP capture", flush=True)
