# ddc

Golang библиотека для формирования и разбора [Карточки электронного документа](https://github.com/kaarkz/ddcard), разработана для сервиса обмена цифровыми подписями [SIGEX](https://sigex.kz).

Так же репозиторий включает в себя пакет [rpcsrv](rpcsrv), экспортирующий функционал библиотеки через [JSON-RPC](https://www.jsonrpc.org/), и соответствующий сервер [rpcsrv/cmd](rpcsrv/cmd).

Документация: [https://pkg.go.dev/github.com/sigex-kz/ddc](https://pkg.go.dev/github.com/sigex-kz/ddc).

Примеры использования библиотеки доступны в [ddc_test.go](ddc_test.go).

Примеры работы через JSON-RPC доступны в [rpcsrv/rpcsrv_test.go](rpcsrv/rpcsrv_test.go).

Сборки JSON-RPC сервера под разные платформы доступны в релизах.

Шаблон файла сервиса для systemd (`/etc/systemd/system/ddc.service`):
```
[Unit]
Description=Digital Document Card RPC srv

StartLimitIntervalSec=60s
StartLimitBurst=10

[Service]
Type=simple
User=ddcrunner
WorkingDirectory=/opt/ddc
ExecStart=/opt/ddc/ddcrpcsrv
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Лицензия: [LICENSE](LICENSE).