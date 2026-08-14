Crontab - это планировщик заданий в Linux, позволяет выполнять действия через определенный период или при наступлении события. Можно использовать как пользовательский cron, так и системные файлы cron ( нужен root ).
/etc/crontab - основной файл, требующий указания пользователя.
/etc/cron.d/ - директория для создания отдельных файлов с задачами.
/etc/cron.minutely - каждую минуту;
/etc/cron.hourly - каждый час;
/etc/cron.daily - каждый день;
/etc/cron.weekly - каждую неделю;
/etc/cron.monthly - каждый месяц.
<img width="974" height="111" alt="image" src="https://github.com/user-attachments/assets/f95dcf27-c20a-4bf8-8836-0bb12ef94a8b" />

<img width="974" height="73" alt="image" src="https://github.com/user-attachments/assets/d98c5775-6ecd-45fe-8f3b-308937403dd9" />

•	Последствия: Если скрипт работает долго и не завершается, новые экземпляры cron могут наслаиваться и перегрузить CPU.
•	Скрытность: Срабатывания видны в /var/log/syslog. Аудит файлов в /etc/cron.d/  выявляет добавление.
