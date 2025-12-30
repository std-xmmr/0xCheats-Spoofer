### 0xCheats-Spoofer
Простой hwid спуфер от 0xCheats для игры SCP Secret Laborotory
Код простой и без лишней хуйни 
На момент разработки спуфера версия SCP SL была - 14.2.4(28.12.2025)

# About code
Интерфейс - MainWindow.xaml
Основной C# код - MainWindow.xaml.cs
Тип проекта - Приложение WPF(.NET Framework - 4.8)

# How To compile
1. paste it in developer powershell - 
   dotnet publish -c Release
2. paste it in developer powershell - 
dotnet clean dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true
3. У вас появиться exe в bin\Release\net10.0-windows\win-x64\publish\

### Features
Processor ID
Motherboard Serial
Network Adapters - MAC Adresses
Disk Drive Serials
SMBIOS Hash
Windows Machine GUID
Windows Product ID
Digital Product ID
User SID
System UUID
Volume Serial Number
Windows Install Date
ARP Cache Steam Profile Traces

### Warning
Для применений изменений которые внес спуфер - нужно перезагрузить компьютер, об этом на прямую пришется в логах ([WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!)
