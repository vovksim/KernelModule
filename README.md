# Firewall Logger – ядровий модуль Linux (навчальний проєкт)

## 1. Запуск зібраної системи в QEMU

### Встановлення QEMU

```bash
sudo apt update
sudo apt install qemu-system-x86
```

### Запуск

```bash
qemu-system-x86_64 \
  -kernel path-to-repo/qemux86-64/bzImage \
  -append "root=/dev/sva rw console=ttyS0" \
  -drive file=path-to-repo/qemux86-64/core-image-minimal-qemux86-64.ext4,format=raw \
  -nographic
```

Для виходу з QEMU: натисніть `Ctrl+A`, потім `X`.

### Вхід у систему

- Логін: `root`
- Пароль: не потрібен

### Перевірка модуля

```bash
dmesg | grep firewall
lsmod | grep firewall_logger
```

## 2. Локальна збірка і запуск модуля

Модуль можна зібрати та протестувати на будь-якій сучасній Linux-системі.

### Вимоги

- GCC, make
- Заголовки ядра (`linux-headers-$(uname -r)`)
- Root-доступ

### Інструкція

```bash
git clone https://github.com/yourname/KernelModule.git
cd KernelModule
make
sudo insmod firewall_logger.ko
dmesg | tail
```

### Видалення модуля

```bash
sudo rmmod firewall_logger
```

## 3. Що робить модуль

Модуль реєструє Netfilter-хук у ядрі та логує IP-пакети (вхідні/вихідні) у системний журнал (`dmesg`). Це дозволяє побачити, як обробляється трафік на рівні ядра.

## 4. Збірка образу Yocto (довідково)

Для створення повного образу використовувалась система Yocto (напр. poky):
- Створено `bzImage` та `core-image.ext4` з вбудованим модулем
