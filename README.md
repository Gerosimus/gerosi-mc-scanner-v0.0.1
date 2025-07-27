# gerosi-mc-scanner-v0.0.1
🧭 Gerosi Minecraft Scanner v0.0.1

GerosiScan - мощный сканер серверов Minecraft с возможностью детального анализа. Работает с Java Edition серверами.


```python gerosi_scaner.py```



🌟 Особенности




    🚀 Асинхронное сканирование - быстрая проверка множества серверов

    🌍 Определение страны по IP (RU, KZ, UA, BY, US, DE, CN)

    📊 Детальная информация о сервере:

        Версия Minecraft

        Онлайн игроков

        Платформа (Forge, Fabric, Optifine и др.)

        Пинг

        Моды (количество и список)

        Статус вайтлиста

    📁 Поддержка различных форматов ввода:

    📁 Поддержка различных форматов ввода:

    Одиночный IP (`192.168.1.1`)

    Домен (`mc.example.com`)

    CIDR-диапазоны (`192.168.1.0/24`)

    Диапазоны IP (`192.168.1.1-192.168.1.100`)

    Файлы со списком серверов


    

📊 Сортировка результатов по разным критериям


📦 Зависимости


`pip install mcstatus colorama`



🛠️ Использование

  1.  Запустите скрипт:

     
     `python gerosi_scaner.py`


  3. Введите цель:

     
       `Примеры: 
    192.168.1.1 
    play.example.com 
    servers.txt 
    10.0.0.0/24`


<img width="700" height="123" alt="{D7AC2AC8-D918-4D49-9C86-F4B5909FC64A}" src="https://github.com/user-attachments/assets/3b0bf55d-531d-4dda-ba05-ed779223dc70" />



     
  5. Выберите сортировку результатов:

     
   `1. По игрокам (↓)
    2. По игрокам (↑)
    3. По пингу (↓)
    4. По пингу (↑)
    5. По модам
    6. По версии
    7. По стране`



<img width="548" height="246" alt="{17ECFCA6-F68B-4A37-80CD-DA82BFFAEC4E}" src="https://github.com/user-attachments/assets/e771e546-cd6e-42e5-aaa9-0bed276f62b2" />





     

📷 Пример вывода





       `IP                     | Version  | Players  | Platform          | Ping   | Mods     | Whitelist  | Country        
        -----------------------------------------------------------------------------------------
        192.168.1.5:25565     | 1.18.2  | 3/20     | Forge 40.1.0     | 42ms   | 12 mods  | Whitelist ON | Russia
        mc.hypixel.net:25565   | 1.8.9   | 54000/54000 | Paper 1.8.8     | 120ms  | 0 mods   | Whitelist OFF | USA`



<img width="1146" height="107" alt="{3C1930A1-8369-4504-AC96-815B82E4D780}" src="https://github.com/user-attachments/assets/a25d8f98-55dd-4595-86b8-ff875c6f2b49" />




        

⚙️ Технические детали

    Логи ошибок сохраняются в ```gerosi_scan_errors.log```

    Поддержка цветного вывода через Colorama

    Автоматическое определение платформы сервера:

        Forge

        Fabric

        Optifine

        Paper

        Spigot

        Vanilla

        И другие


<img width="529" height="73" alt="{1600EB2E-0245-4DEF-8744-D440CDBA58E5}" src="https://github.com/user-attachments/assets/e8c802ec-4ed6-41b5-87b4-555c7964ef75" />





📄 Лицензия

MIT License. Используйте на свой страх и риск.
     

    


