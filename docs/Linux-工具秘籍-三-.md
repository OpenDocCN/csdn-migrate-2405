# Linux 工具秘籍（三）

> 原文：[`zh.annas-archive.org/md5/CA17A1452E9A171FA85666D109FEB63D`](https://zh.annas-archive.org/md5/CA17A1452E9A171FA85666D109FEB63D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：使用 Cron 自动化任务

在本章中，我们将涵盖：

+   创建和运行 crontab 文件

+   每隔一周运行一个命令

+   报告来自 crontab 文件的错误

# 介绍

cron 守护程序通常由操作系统自动启动，每分钟查看所有 crontab 文件。如果满足了标准，就会运行命令。在本章中，我们将展示如何使用 crontab 程序创建和维护您的 crontab 文件。

根据系统设置的方式，cron 作业是否允许（允许或不允许）取决于用户。控制这一点的文件位于`/etc`中，命名为`cron.allow`和`cron.deny`。这些将在以下部分中解释：

+   `cron.allow`：如果此文件存在，则用户必须在其中列出，才能使用 crontab

+   `cron.deny`：如果`cron.allow`不存在但`cron.deny`存在，则用户不得列在`cron.deny`文件中

如果两个文件都不存在，则只有 root 用户可以使用该命令。在大多数 Linux 系统中，只有`cron.deny`存在且为空。在运行以下命令之前，请在您的系统上检查这一点。

我们将使用一个用户帐户来尝试 crontab。`crontab`命令用于对 crontab 文件进行更改，不应直接编辑。要查看当前用户的 crontab，请运行`crontab -l`。

编辑当前用户的 crontab 文件的命令是`crontab -e`。默认情况下，这将在 vi 编辑器中打开 crontab 文件。但是，您可以更改`EDITOR`环境变量以使用任何文本编辑器。

以下是典型用户 crontab 文件的格式：

```
#
#  crontab for jklewis
# Field 1   2    3            4              5             6
#      Min Hour Day of month Month of year  Day of week
#     0-59 0-23 1-31         1-12           0-6   0=Sun /path/command
#
# Days of the week: 0=Sun 1=Mon 2=Tues 3=Wed 4=Thu 5=Fri 6=Sat

```

我总是将此模板添加到 crontab 文件的顶部，以便我可以轻松记住这些字段是什么。以下是一个示例 crontab 条目：

```
 10     0     *     *     0     /path/mycommand

```

这些值可以是整数、范围、元素或元素列表，或星号。星号表示匹配所有有效值。

+   `#`：这表示一行被注释。它必须是行上的第一件事（不要把它放在行的末尾）。

+   **字段 1**：这是分钟。它从 0 开始，意味着 00:00。

+   **字段 2**：这是小时。它从 0 开始，意味着凌晨 12:00。

+   **字段 3**：这是一个月中的日期。

+   **字段 4**：这是一年中的月份。也可以使用名称。

+   **字段 5**：这是一周中的日期。它从 0 开始，即星期日。也可以使用名称。

+   **字段 6**：这是要运行的路径/命令。

此示例条目将在每个星期日的凌晨 12:10 运行`mycommand`。

### 提示

只使用空格来分隔字段。不要使用制表符。

# 创建和运行 crontab 文件

在这里，我们将展示创建和运行用户 crontab 文件的示例。

## 准备工作

确保您的系统按照*介绍*中概述的方式设置。我们将使用两个终端会话，以便更容易地查看我们的结果。

## 如何做...

以下是创建和运行 crontab 文件的示例：

1.  在终端会话中运行`tty`并记住输出。这将在第 10 步中使用。

1.  打开或使用另一个终端，使用用户帐户。我将使用`jklewis`，就像在前几章中一样。

1.  让我们通过运行以下命令来查看 crontab 文件：

```
crontab -l

```

1.  它可能会说类似于`jklewis 没有 crontab`，这是可以接受的。

1.  现在让我们通过运行以下命令来创建一个：

```
crontab -e

```

1.  它可能会说类似于`jklewis 没有 crontab - 使用空的`，这是好的。

1.  Crontab 应该在 vi 中打开一个临时文件（除非您已更改了`EDITOR`变量，就像我在我的系统上做的那样）。在保存文件并结束会话之前，文件不会被使用。

1.  我建议将我上面创建的模板剪切并粘贴到您的 crontab 文件中。这将使您更容易记住这些字段。

1.  现在让我们添加一个条目，我们可以看到效果很快。将以下行插入文件（剪切和粘贴应该有效）：

```
TTY=/dev/pts/17
# crontab example 1
*   *   *    *    *     date > $TTY; echo "Yes it works" > $TTY

```

1.  将`TTY`行更改为您在步骤 1 中找到的内容。

1.  现在保存文件并退出会话。您应该会看到以下消息：

```
crontab: installing new crontab

```

1.  在接下来的一分钟内，您应该在另一个会话中看到以下输出：

```
Tue May  7 19:52:01 CDT 2013
Yes it works

```

1.  我们刚刚使用所有这些星号创建的条目意味着每分钟运行一次命令。再次编辑 crontab 并将行更改为以下代码：

```
*/5    *   *   *   *   date > $TTY; echo "Every 5 minutes"  > $TTY

```

1.  那种奇怪的语法是一种跳过或增加值的方法。现在尝试以下命令：

```
35     9     *     *     1-5   date > $TTY; echo "9:35 every week day"  > $TTY

```

1.  每周一至周五上午 9:35 运行。日期字段中的 1-5 是一个范围。

1.  名称也可以用于日期和月份字段，如以下命令：

```
17   13    8     May   Wed   date > $TTY; echo "May 8 at  13:17"  > $TTY

```

1.  以及以下命令：

```
0   0    *     *      Fri   date > $TTY; echo "Run every  Friday at 12:00 am"  > $TTY

```

对于名称，使用标准的三个字母缩写，大小写不重要。使用名称可能更容易，但是您不能在名称中使用范围或步长。

# 每隔一周运行一次命令

现在我们已经了解了 cron 的基础知识，您将如何设置条目以每隔一周运行一次命令？您可能会尝试类似以下代码的东西：

```
 *  *  *  *  0/2   /path/command

```

这意味着从星期日开始，然后每隔一周运行一次，对吗？不，这是错误的，但是您经常会在网站上看到这样的解决方案。Cron 实际上没有内置的方法来做到这一点，但有一个解决方法。

## 操作步骤如下...

以下是每隔一周运行命令的步骤：

1.  在您的主目录中创建以下脚本，并将其命名为`cron-weekly1`（随意剪切和粘贴）：

```
#!/bin/sh
# cron-weekly1
# Use this script to run a cron job every other week
FN=$HOME/cron-weekly.txt
if [ -f $FN  ] ; then
 rm $FN
 exit
fi
touch $FN
echo Run the command here

```

1.  通过运行以下命令使脚本可执行：

```
chmod 755 cron-weekly1

```

1.  通过运行以下命令在您的用户帐户下运行：

```
crontab -e

```

1.  添加以下行：

```
 0  0  *  *  0    $HOME/cron-weekly1

```

1.  结束您的编辑会话。这将安装修改后的 crontab 文件。

## 工作原理...

看看这个脚本。第一次运行时，`cron-weekly.txt`文件不存在，因此它会被创建，并且会执行命令（您想每隔一周运行的命令）。下周，当再次运行此脚本时，它会看到`cron-weekly.txt`文件存在，然后删除它，然后退出脚本（不运行命令）。这样每周交替进行，有效地每隔一周运行一次命令。很酷，对吧？

在前面的`cron-weekly1`脚本中，命令在第一次运行脚本时执行。您可以通过将运行命令的行移动到`if`语句内部来更改为从下一周开始运行命令。

尽管这样做可能非常诱人，但不要在行尾加上注释`#`。Cron 无法判断它是注释还是命令的一部分。如果 cron 报告了一些您不理解的错误，请检查放错位置的注释。是的，我承认我偶尔还会这样做。

如果您做了 cron 不喜欢的事情（例如在前面部分显示的`* * * * 0/2 command`行），当您关闭会话时它通常会报告错误。然后它会给您重新编辑文件的选项。务必这样做，要么解决问题，要么至少注释该行。您可以稍后返回并再次编辑它。

您可以通过运行`crontab -r`完全删除 crontab 文件。我建议在执行此操作之前先备份文件，以防万一。您应该能够通过您选择使用的任何文本编辑器将文件保存为新名称。

## 还有更多...

Crontab 文件可以使用环境变量。以下是一些常见的环境变量：

+   **SHELL**：这告诉操作系统使用特定的 shell，覆盖了`/etc/passwd`文件中的内容。例如，`SHELL=/bin/sh`。

+   **MAILTO**：这告诉 cron 将错误邮寄给此用户。语法是`MAILTO=<user>`，即`MAILTO=jklewis`。

+   **CRON_TZ**：用于设置特定的时区变量，即`CRON_TZ=Japan`。

Cron 有一些快捷方式可供使用。这些用于替代 5 个时间和日期字段，如下所示：

| 命令的快捷方式 | 命令 | 输出 |
| --- | --- | --- |
| **@reboot** |   | 重启后运行一次 |
| **@yearly or @annually** | **0 0 1 1 *** | 每年的第一天 |
| **@monthly** | **0 0 1 * *** | 每月第一天 |
| **@weekly** | **0 0 * * 0** | 每周日凌晨 12:00 运行 |
| **@daily** | **0 0 * * *** | 每天凌晨 12:00 运行 |
| **@hourly** | **0 * * * *** | 每小时整点运行 |

因此，在前面的示例中，我们可以放置`@weekly $HOME/cron-weekly1`。

不要将 cron 用于任何时间敏感的任务。通常在运行命令之前会有短暂的延迟，只有几秒钟。如果您需要更好的粒度，可以使用脚本和 sleep 例程。

您还可以为 root 设置一个 crontab。要了解更多信息，请使用`man -a crontab`。

# 报告 crontab 文件中的错误

您可能会想知道，如果 crontab 文件中有错误，计算机会如何报告它？它通过使用 sendmail 系统向 crontab 用户发送邮件来完成此操作。

## 如何做...

以下是 cron 报告错误的示例：

1.  使用用户帐户打开终端。

1.  通过运行以下命令编辑您的 crontab 文件：

```
crontab -e

```

1.  现在让我们故意引发一个错误。滚动到底部并添加以下行：

```
* * * *    date > /baddirectory/date.txt

```

1.  保存文件。等到 cron 在下一分钟运行，然后在用户终端中按*Enter*。

1.  您应该看到一条消息，说您有邮件。运行以下命令：

```
mail

```

1.  应该有一封邮件指示错误（在本例中，文件未找到）。您可以通过按下*D*然后按*Q*来删除邮件。

1.  最后，确保重新编辑您的 crontab 文件并删除我们刚刚添加的错误行。

## 还有更多...

您还可以监视`/var/log/cron`文件，以查看系统在一天中的运行情况。当首次创建 crontab 文件并尝试使其正确时，这非常有帮助。


# 第十章： 内核

在本章中，我们将涵盖以下主题：

+   对模块命令的简要介绍

+   从 kernel.org 构建内核

+   使用 xconfig 修改配置

+   使用 GRUB

+   了解 GRUB 2

# 介绍

内核是操作系统的主要组件或核心。 它控制系统中的所有资源，时间，中断，内存分配，进程分离，错误处理和日志记录。 在典型的 Linux 计算机中，内核是模块化的，它具有核心文件（或文件），然后根据需要加载其他设备驱动程序。 在某些情况下，比如嵌入式设备，内核可能由一个包含所有所需驱动程序的大图像文件组成。 这被称为单片内核。

在决定是否需要构建自定义内核之前，您应该首先确保自己确实需要一个。 运行自定义内核的利弊如下。

以下是运行自定义内核的优点：

+   如果您知道自己在做什么并且有时间进行研究，您可以得到最大化硬件性能的内核

+   您可以利用股票内核可能没有的功能或设备

+   通过查看所有内核设置，您可以更好地了解 Linux

+   构建和运行自己的内核只是纯粹的乐趣

以下是运行自定义内核的缺点：

+   您自己的自定义内核可能不包含发行版所需的功能

+   VMware 和其他虚拟环境可能需要额外的努力才能正常工作

+   请注意，如果运行自己的内核，您很可能不再得到发行版支持渠道的支持

### 提示

运行自己的内核的大多数缺点都可以解决。 这取决于您花多少时间来解决它。

# 对模块命令的简要介绍

有几个命令用于操作系统上的模块。 请注意，根据您的发行版，这些命令可能只能以 root 身份运行。

## 如何做...

在以下步骤中，我们将运行`lsmod`，`modprobe`，`insmod`和`modinfo`命令：

1.  要查看系统上当前加载的模块的状态，请运行`lsmod`。

1.  要从当前的`/lib/modules/<kernel name>`目录加载模块，您将使用`modprobe`命令。 例如`modprobe pcnet32`。

1.  直接加载模块，使用`insmod`命令。 例如`insmod /temp/pcnet32.ko`。

1.  要显示有关模块的信息，请使用`modinfo`命令。 首先运行`lsmod`查找模块，然后在其中一个名称上尝试`modinfo`。

## 工作原理...

`lsmod`命令获取`/proc/modules`文件的内容并以易于阅读的格式显示出来。 使用它来确定系统中加载了哪些模块。

以下屏幕截图显示了我 Fedora 19 系统中`lsmod`的部分列表：

![工作原理...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_10_00.jpg)

`modprobe`命令用于向 Linux 内核添加和删除模块。 它从当前的`/lib/modules/<kernel name>`目录加载模块。 `modprobe`命令比`insmod`做得更多，例如一次加载多个模块以解决依赖关系，并且通常优先于`insmod`。 由于`modprobe`可以加载多个模块，因此`/etc/modprobe.d`中的文件和`/etc/modules.conf`文件用于解决任何问题。

`insmod`命令可用于将模块插入系统。 通常用于直接加载模块。 例如，如果您想加载新创建的`pcnet32`模块的版本，您首先会将目录更改为正确的目录，然后运行`insmod pcnet32.ko`。

`modinfo`命令显示有关 Linux 内核模块的信息。这是一个非常有用的命令，允许您查看特定模块的详细信息，例如它将接受哪些参数。以下是在我的 Fedora 17 系统上从`modinfo`输出的样子：

```
BIG2 /temp/linux-3.9.1 # modinfo nouveau
filename:       /lib/modules/3.6.1-1.fc17.x86_64/kernel/drivers/gpu/drm/nouveau/nouveau.ko
license:        GPL and additional rights
description:    nVidia Riva/TNT/GeForce
author:         Stephane Marchesin
alias:          pci:v000012D2d*sv*sd*bc03sc*i*
alias:          pci:v000010DEd*sv*sd*bc03sc*i*
depends:        drm,drm_kms_helper,ttm,mxm-wmi,i2c-core,wmi,video,i2c-algo-bit
intree:         Y
vermagic:       3.6.1-1.fc17.x86_64 SMP mod_unload
parm:           agpmode:AGP mode (0 to disable AGP) (int)
parm:           modeset:Enable kernel modesetting (int)
parm:           vbios:Override default VBIOS location (charp)
parm:           vram_pushbuf:Force DMA push buffers to be in VRAM (int)
parm:           vram_notify:Force DMA notifiers to be in VRAM (int)
parm:           vram_type:Override detected VRAM type (charp)
parm:           duallink:Allow dual-link TMDS (>=GeForce 8) (int)
parm:           uscript_lvds:LVDS output script table ID (>=GeForce 8) (int)
parm:           uscript_tmds:TMDS output script table ID (>=GeForce 8) (int)
parm:           ignorelid:Ignore ACPI lid status (int)
parm:           noaccel:Disable all acceleration (int)
parm:           nofbaccel:Disable fbcon acceleration (int)
parm:           force_post:Force POST (int)
parm:           override_conntype:Ignore DCB connector type (int)
parm:           tv_disable:Disable TV-out detection (int)
parm:           tv_norm:Default TV norm.
 Supported: PAL, PAL-M, PAL-N, PAL-Nc, NTSC-M, NTSC-J, hd480i, hd480p, hd576i, hd576p, hd720p, hd1080i.
 Default: PAL
 *NOTE* Ignored for cards with external TV encoders. (charp)
parm:           reg_debug:Register access debug bitmask:
 0x1 mc, 0x2 video, 0x4 fb, 0x8 extdev, 0x10 crtc, 0x20 ramdac, 0x40 vgacrtc, 0x80 rmvio, 0x100 vgaattr, 0x200 EVO (G80+) (int)
parm:           perflvl:Performance level (default: boot) (charp)
parm:           perflvl_wr:Allow perflvl changes (warning: dangerous!) (int)
parm:           msi:Enable MSI (default: off) (int)
parm:           ctxfw:Use external HUB/GPC ucode (fermi) (int)
parm:           mxmdcb:Santise DCB table according to MXM-SIS (int)

```

`rmmod`命令允许您从 Linux 内核中删除已加载的模块。通常的语法是`rmmod modulename`。不使用扩展名。您也可以使用`modprobe -r`命令。

`depmod`程序生成`modules.dep`和`.map`文件。通常情况下，用户不需要手动执行它，因为它在内核构建期间运行。它通过检查`/lib/modules/<kernelname>`中的模块并确定它们需要哪些符号以及它们导出哪些符号来创建模块依赖列表。

其中一些命令有一个强制选项。它将尝试执行所需的功能，绕过任何检查。我从未见过这种方法可靠地工作，因此不建议使用。如果您决定尝试，请确保您有完整的操作系统备份。

在运行设备驱动程序命令时，通常可以通过查看`/var/log/messages`文件获得更多信息。我建议打开一个终端并在其中运行`tail -f /var/log/messages`。始终保持这个终端可见。还要注意，该文件最终会被回收，因此命令将不得不停止并重新启动（在我的系统上大约每周一次）。一个简单的测试是运行`logger hellojim`。如果你没有看到它出现，那么是时候重新启动 tail 会话了。

您还可以运行`dmesg`命令。以下是 Fedora 17 上`dmesg`输出的一个简短示例：

```
Linux version 3.6.1-1.fc17.x86_64 (mockbuild@) (gcc version 4.7.2 20120921 (Red Hat 4.7.2-2) (GCC) ) #1 SMP Wed Oct 10 12:13:05 UTC 2012
Command line: BOOT_IMAGE=/vmlinuz-3.6.1-1.fc17.x86_64 root=/dev/mapper/vg_bigtwo-lv_root ro rd.md=0 rd.dm=0 SYSFONT=True rd.lvm.lv=vg_bigtwo/lv_swap KEYTABLE=us rd.lvm.lv=vg_bigtwo/lv_root LANG=en_US.UTF-8 rd.luks=0 rhgb quiet
smpboot: Allowing 4 CPUs, 2 hotplug CPUs
Booting paravirtualized kernel on bare hardware
Kernel command line: BOOT_IMAGE=/vmlinuz-3.6.1-1.fc17.x86_64 root=/dev/mapper/vg_bigtwo-lv_root ro rd.md=0 rd.dm=0 SYSFONT=True rd.lvm.lv=vg_bigtwo/lv_swap KEYTABLE=us rd.lvm.lv=vg_bigtwo/lv_root LANG=en_US.UTF-8 rd.luks=0 rhgb quiet
Memory: 3769300k/5242880k available (6297k kernel code, 1311564k absent, 162016k reserved, 6905k data, 1032k init)
Console: colour dummy device 80x25
tsc: Fast TSC calibration using PIT
tsc: Detected 2699.987 MHz processor
CPU: Processor Core ID: 0
CPU0: Thermal monitoring enabled (TM2)
smpboot: CPU0: Intel Pentium(R) Dual-Core  CPU      E5400  @ 2.70GHz stepping 0a
NMI watchdog: enabled on all CPUs, permanently consumes one hw-PMU counter.
smpboot: Booting Node   0, Processors  #1
smpboot: Total of 2 processors activated (10799.94 BogoMIPS)
atomic64 test passed for x86-64 platform with CX8 and with SSE
NET: Registered protocol family 38
Block layer SCSI generic (bsg) driver version 0.4 loaded (major 252)
Console: switching to colour frame buffer device 80x30
fb0: VESA VGA frame buffer device
input: Power Button as /devices/LNXSYSTM:00/device:00/PNP0C0C:00/input/input0
ACPI: Power Button [PWRB]
Serial: 8250/16550 driver, 4 ports, IRQ sharing enabled
Non-volatile memory driver v1.3
Linux agpgart interface v0.103
ACPI: PCI Interrupt Link [LSA0] enabled at IRQ 21
ata1: SATA max UDMA/133 abar m8192@0xfe9fc000 port 0xfe9fc100 irq 21
usb usb1: New USB device found, idVendor=1d6b, idProduct=0002
usb usb1: Manufacturer: Linux 3.6.1-1.fc17.x86_64 ehci_hcd
usb usb1: SerialNumber: 0000:00:04.1
hub 1-0:1.0: USB hub found
hub 1-0:1.0: 8 ports detected
usb usb2: Manufacturer: Linux 3.6.1-1.fc17.x86_64 ohci_hcd
usb usb2: SerialNumber: 0000:00:04.0
usbcore: registered new interface driver usbserial
usbcore: registered new interface driver usbserial_generic
USB Serial support registered for generic
usbserial: USB Serial Driver core
serio: i8042 KBD port at 0x60,0x64 irq 1
serio: i8042 AUX port at 0x60,0x64 irq 12
mousedev: PS/2 mouse device common for all mice
rtc0: alarms up to one year, y3k, 114 bytes nvram, hpet irqs
device-mapper: uevent: version 1.0.3
device-mapper: ioctl: 4.23.0-ioctl (2012-07-25) initialised: dm-devel@redhat.com
cpuidle: using governor ladder
cpuidle: using governor menu
drop_monitor: Initializing network drop monitor service
ip_tables: (C) 2000-2006 Netfilter Core Team
input: AT Translated Set 2 keyboard as /devices/platform/i8042/serio0/input/input2
ata1: SATA link up 3.0 Gbps (SStatus 123 SControl 300)
ata1.00: ATA-8: WDC WD5000AAVS-00N7B0, 01.00A01, max UDMA/133
ata1.00: 976773168 sectors, multi 0: LBA48 NCQ (depth 31/32)
ata1.00: configured for UDMA/133
scsi 0:0:0:0: Direct-Access     ATA      WDC WD5000AAVS-0 01.0 PQ: 0 ANSI: 5
Freeing unused kernel memory: 1032k freed
Write protecting the kernel read-only data: 12288k
nouveau 0000:00:10.0: setting latency timer to 64
[drm] nouveau 0000:00:10.0: Detected an NV40 generation card (0x063000a2)
Console: switching to colour dummy device 80x25
usb 1-6: New USB device found, idVendor=0bda, idProduct=0181
Initializing USB Mass Storage driver...
scsi4 : usb-storage 1-6:1.0
tsc: Refined TSC clocksource calibration: 2699.931 MHz
usb 2-3: Manufacturer: American Power Conversion
hid-generic 0003:051D:0002.0001: hiddev0,hidraw0: USB HID v1.00 Device [American Power Conversion Back-UPS RS 700G FW:856.L3 .D USB FW:L3  ] on usb-0000:00:04.0-3/input0
EXT4-fs (dm-1): mounted filesystem with ordered data mode. Opts: (null)
e1000: Intel(R) PRO/1000 Network Driver - version 7.3.21-k8-NAPI
e1000: Copyright (c) 1999-2006 Intel Corporation.
r8169 0000:04:00.0: irq 43 for MSI/MSI-X
r8169 0000:04:00.0: eth0: RTL8102e at 0xffffc90010fae000, 44:87:fc:69:4d:0f, XID 04c00000 IRQ 43
microcode: CPU0 updated to revision 0xa0b, date = 2010-09-28
ALSA sound/pci/hda/hda_intel.c:1593 Enable delay in RIRB handling

```

## 还有更多...

查阅这些命令的 man 或 info 页面以获取更多信息。特别是查看`man modprobe.conf`，了解如何使用`modprobe`的配置选项。

您可以使用`uname -r`命令查看当前的内核版本。通常情况下，您会发现在脚本和别名中使用`uname -r`表达式效果很好。

# 从 kernel.org 构建内核

在这个示例中，我们将使用来自[`kernel.org`](http://kernel.org)网站的内核文件。

## 准备工作

在不会对系统造成任何可能的伤害的情况下，您应该能够执行除了最后一步之外的所有步骤。`make install`命令将修改您的 GRUB 文件，因此至少我会备份这些文件。为了更安全，因为我们已经知道我是偏执的，如果您要安装新的内核，我建议在测试机器上运行所有这些步骤。

这个示例假设您的计算机已安装为完整的开发系统。您将需要最新版本的`GCC`，`make`，QT 开发包等。如果您选择安装了当前发行版的软件开发包（或等效包），那么您可能已经准备就绪。我建议在您计划进行构建的分区上至少有 10GB 的文件空间可用；如果您将要创建大量的内核树（内核 3.9.1 中的文件使用了 6.5GB），则需要更多。

`vmlinuz`，`initramfs`和`map`文件将被复制到`/boot`，因此请确保它足够大，以处理您想要的额外内核的数量（大约 500MB 是典型的）。

您需要以 root 身份运行`make modules_install`和`make install`命令。我建议在整个过程中都以 root 身份运行，以避免任何文件权限问题。

## 如何做...

以下是获取和构建内核的步骤：

1.  在您的浏览器中，导航到[`kernel.org`](http://kernel.org)。

1.  点击黄色方框内的**Latest Stable Kernel**，并保存文件。在 Fedora 上，`Downloads`目录是`/home/<user>/Downloads`。

1.  您想要构建的位置基本上取决于您。我个人不喜欢很长的目录路径，所以我把我的放在`/temp`目录中。如果您愿意，您可以选择另一个位置。

1.  将`.xz`文件从`Downloads`目录复制或移动到`/temp`。在本例中，文件名是`linux-3.9.1.tar.xz`。

1.  切换到`/temp`目录并提取文件`tar xvf linux-3.9.1.tar.xz`。这以前需要很长时间，但现在也不太糟糕。

1.  完成后，切换到`cd /temp/linux-3.9.1`目录。

1.  下一步是获取一个内核配置文件。除非你已经有一个特定的文件在脑海中，我通常从`/boot`目录中取最新的一个。在我的系统上，我运行了以下命令：

```
cp /boot/config-3.6.1-1.fc17.x86_64

```

1.  您可以直接复制文件到`.config`，但是，我喜欢看到我从哪里开始。现在就这样做：

```
cp config-3.6.1-1.fc17.x86_64  .config

```

1.  现在我们需要运行一个内核构建程序来使一切同步。我们将使用`xconfig`程序，这将在下一节中详细讨论。现在，只需运行以下命令：

```
make xconfig

```

1.  这将带来一个看起来很酷的屏幕，上面有大约一百万个东西。点击**文件** | **保存**，然后**文件** | **退出**。

1.  现在您应该回到文本屏幕，显示类似以下内容：

```
Big4 /temp/linux-3.9.1 # make xconfig
 HOSTCC  scripts/kconfig/conf.o
 HOSTCC  scripts/kconfig/zconf.tab.o
 HOSTCXX scripts/kconfig/qconf.o
 HOSTLD  scripts/kconfig/qconf
scripts/kconfig/qconf Kconfig
#
# configuration written to .config
#

```

1.  现在运行`make`命令。根据您的计算机速度，这可能需要很长时间。如果你喝咖啡或茶，这可能是一个去喝一些的好时机。

1.  检查确保没有错误，然后运行以下命令：

```
make modules_install

```

1.  下一步将修改您的 GRUB 配置。我总是确保我有备份以防万一。完成后，要安装内核，请运行以下命令：

```
make install

```

1.  在大多数情况下，`make install`命令将设置新内核为默认值。您可以通过查看 GRUB 配置文件来检查这一点（我们稍后将在本章中看到更多关于 GRUB 的内容）。

1.  要实际尝试新的内核，您必须重新启动系统（稍后会详细介绍）。当屏幕出现时，请确保菜单上选择了正确的内核。

1.  由于我们没有进行实质性的更改，内核应该可以正常启动。通过运行`uname -a`命令来检查是否启动了正确的内核。您不应该在这个内核中看到或注意到任何差异。但是，根据几个因素，它可能不像预期的那样工作，甚至可能根本无法启动。如果是这种情况，您应该能够重新启动到之前的良好内核。

重新启动时，我强烈建议进行冷启动。执行有序关机（`shutdown -h now`），让机器至少静置几秒钟；几分钟也不会有什么坏处。我曾经看到一些非常奇怪的事情发生在热启动上，任何理智的人都会说这是不可能的。

# 使用 xconfig 修改配置

如前一节所述，`.config`文件控制着进入内核文件的一切。这包括`vmlinuz`和`initramfs`文件，以及设备驱动程序模块。`.config`是一个文本文件，但不是直接编辑的，而是可以使用几种不同的程序之一。在本章中，我们将向您展示如何使用`xconfig`程序来对`.config`文件进行更改。

## 准备工作

在执行这些步骤之前，请参阅前一节中有关准备工作的内容。

## 如何做...

在这里，我们将使用`xconfig`来修改配置：

1.  切换到内核构建目录并运行以下命令：

```
make xconfig

```

1.  那个看起来很酷的屏幕应该再次出现。这个程序需要几分钟来适应，所以我们将一步一步地进行。

1.  首先，找到字符串**处理器类型和特性**并点击。屏幕会发生变化。

1.  现在，在右侧面板下的**处理器系列**下，点击**Core 2/newer Xeon**。点击文本，*而不是*单选按钮。

1.  现在您应该看到类似以下截图的内容（来自我使用 3.9.9 内核的 Fedora 19 系统）：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_10_01.jpg)

1.  在使用这个程序时必须小心。很容易意外点击单选按钮，改变你不打算改变的东西。因此，我建议频繁备份你的`.config`文件。由于它是一个文本文件，你可以使用`diff`程序查看文件之间的更改。如果你不熟悉`diff`，运行`man diff`获取更多信息。

1.  所以，让我们继续改变一些东西。如果你正在运行现代硬件，它可能有一个 Core 2 或 Xeon 处理器。运行`cat /proc/cpuinfo`查看你有什么。如果看起来合适，点击**Core 2/newer Xeon**行上的单选按钮。

1.  这些是配置新内核的基础。刚开始时，我建议在构建之间尽量少做更改。这样，如果出现问题，跟踪导致问题的更改将更容易。

1.  完成对`xconfig`的讨论，让我们尝试另一个字段。在左侧，点击**常规设置**的文本。

1.  你会看到右侧的文本发生变化。通常，在使用`xconfig`时，你点击文本来改变显示，点击适当的按钮来展开或压缩条目，点击单选按钮来实际更改值。方框中的小黑点表示将构建一个模块。

## 还有更多...

你可以使用`diff`命令查看你保存的`.config`文件之间的差异。在调试时，这将节省大量时间。

这个程序可能有些令人困惑。在某些地方，右侧的文本会指示**在此处选择 Y**。这意味着确保复选框中有一个勾。同样，**No**表示没有勾选。在某些情况下，程序会说在一个没有复选框的字段中指示 Y 或 N。我想这些是错误，如果是的话，它们已经存在很长时间了。

你也可以点击**帮助** | **介绍**，了解如何使用`xconfig`的简要信息。

在构建内核时必须格外小心。在使用`xconfig`修改`.config`文件时很容易出错，导致内核无法启动。以下是一些要点：

+   每次更改时都要备份当前的`.config`文件。

+   尽量一次性做尽可能少的更改。试图通过做很多更改来节省时间是很诱人的，如果这对你有效那太好了。但对我来说行不通。

+   如果你的最新内核无法启动，请尝试使用`diff`来比较你的最新`.config`文件和上一个好的文件。你可能能够立即发现问题。

+   如果一切失败，回到已知的工作配置文件，然后从那里重新开始。你一直在备份你的`.config`文件，对吧？

# 使用 GRUB

在处理内核时，你可能需要不时地更改你的 GRUB 配置文件。你可以修改默认启动的内核，内核选择菜单的超时值，传递给内核的参数，启动其他操作系统，以及许多其他内容。

`grub.conf`文件通常位于`/boot/grub`中，或者你可以使用`/etc/grub.conf`文件，它是一个符号链接。

以下是我在我的 Fedora 14 系统上的`grub.conf`的样子：

```
# grub.conf generated by anaconda
#
# Note that you do not have to rerun grub after making changes to this file
# NOTICE:  You have a /boot partition.  This means that
#          all kernel and initrd paths are relative to /boot/, eg.
#          root (hd0,0)
#          kernel /vmlinuz-version ro root=/dev/sda3
#          initrd /initrd-[generic-]version.img
default=2
timeout=5
splashimage=(hd0,0)/grub/splash.xpm.gz
hiddenmenu
title Fedora (3.9.1)
 root (hd0,0)
 kernel /vmlinuz-3.9.1 ro  root=UUID  rhgb quiet
 initrd /initramfs-3.9.1.img
title Fedora (2.6.38.4)
 root (hd0,0)
 kernel /vmlinuz-2.6.38.4 ro root=UUID rhgb quiet
 initrd /initramfs-2.6.38.4.img
title Fedora (2.6.35.6-45.fc14.x86_64)
 root (hd0,0)
 kernel /vmlinuz-2.6.35.6-45.fc14.x86_64 ro root=UUID rhgb quiet
 initrd /initramfs-2.6.35.6-45.fc14.x86_64.img

```

## 如何做...

在这里，我们将向你展示如何更改`grub.conf`文件中的一些项目。请注意，这里的错误可能导致系统无法启动，所以要么只是跟着做，要么非常小心。

1.  切换到正确的目录：

```
cd /etc

```

1.  备份副本：`cp grub.conf /temp`（或其他适当的位置）。

1.  用 vi 或等效工具进行编辑：

```
vi grub.conf

```

1.  参考上面的文件，让我们默认启动第一个段落。将`default=2`行更改为`default=0`。请注意，它们从 0 开始计数。

1.  现在让我们增加等待你进行选择的时间；将`timeout`值更改为`10`。

1.  假设你想以文本模式启动，要做到这一点，请注释掉（即在前面加上`#`）`splashimage`和`hiddenmenu`行。

1.  并且从段落（或所有段落）中删除`rhgb quiet`。

1.  如果你有任何要传递给内核的参数，你可以直接添加到`kernel`行的末尾。

## 它是如何工作的...

让我们在下一节中看一下上述步骤的分解：

+   注释部分说`你有一个/boot 分区。这意味着所有内核和 initrd 路径都是相对于/boot 的`。这是在试图说的是，当你遇到后面包含类似`/vmlinuz-3.9.1`的行时，它实际上意味着`/boot/vmlinuz-3.9.1`。不要忘记它是这样工作的，你以后会省去很多麻烦。

+   `default=2`表示使用第三个标题或段落（是的，这又是另一个从 0 开始计数而不是从 1 开始计数的地方）。

+   `timeout=5`表示在启动默认内核之前显示内核启动菜单 5 秒钟。

+   `splashimage`行在启动时在屏幕上显示一个图形图像。我非常不喜欢这个，所以我把它注释掉了。

+   `hiddenmenu`行表示隐藏内核启动菜单。取消注释此行以显示菜单。是的，又是反过来，但不像从 0 开始计数那么尴尬。

+   第一行标题开始一个内核段。在该行和下一个标题行（或文件结束）之间的所有内容都与该内核相关联。在这种情况下，列出的第一个内核是我创建的最新的一个（3.9.1）。

+   `root (hd0,0)`行表示我的`/boot`目录位于第一个硬盘的第一个分区上。

+   下一行是实际的内核文件和参数。

+   这个段落的最后一行是初始的 RAM 磁盘映像文件。

+   如你所见，这台机器上还有两个更多的段落（内核）可用。我正在运行`2.6.35-6-45.fc14.x86_64`，这是 Fedora 14 64 位的默认内核。

# 理解 GRUB 2

GRUB 2 现在被许多 Linux 发行版使用。这是一个完全的重写，旨在解决 GRUB Legacy 中的一些问题。它仍在开发中，因此这里的信息可能不完整或过时。

使用 GRUB 2 时的引导配置在`/boot/grub2/grub.cfg`文件中。你也可以通过`/etc/grub2.cfg`文件来引用它，这是一个符号链接。

以下是我在我的 Fedora 17 系统上看到的前几行的样子：

```
#
# DO NOT EDIT THIS FILE
#
# It is automatically generated by grub2-mkconfig using templates
# from /etc/grub.d and settings from /etc/default/grub
#
### BEGIN /etc/grub.d/00_header ###
if [ -s $prefix/grubenv ]; then
 load_env
fi
set default="1"
if [ x"${feature_menuentry_id}" = xy ]; then
 menuentry_id_option="--id"
else
 menuentry_id_option=""
fi

```

正如注释行所说，这个文件不是用来直接编辑的。相反，`/etc/default/grub`文件与`/etc/grub.d`目录中的一组文件一起使用。

```
Big2 /etc/grub.d # ls -la
total 76
drwx------.   2 root root  4096 Oct 18  2012 .
drwxr-xr-x. 167 root root 12288 May 15 03:34 ..
-rwxr-xr-x.   1 root root  7528 Aug  2  2012 00_header
-rwxr-xr-x.   1 root root  9265 Aug  2  2012 10_linux
-rwxr-xr-x.   1 root root  9948 Aug  2  2012 20_linux_xen
-rwxr-xr-x.   1 root root  2564 Aug  2  2012 20_ppc_terminfo
-rwxr-xr-x.   1 root root  9339 Aug  2  2012 30_os-prober
-rwxr-xr-x.   1 root root   214 Aug  2  2012 40_custom
-rwxr-xr-x.   1 root root   216 Aug  2  2012 41_custom
-rw-r--r--.   1 root root   483 Aug  2  2012 README

```

## 如何做...

以下是使用 GRUB 2 时对引导配置进行更改的步骤。记住，`grub.cfg`文件不是直接编辑的；而是对`/etc/grub.d`目录中的文件进行更改。

1.  让我们改变`timeout`和`rhgb`的值。编辑`/etc/default/grub`文件。

1.  将`GRUB_TIMEOUT`更改为`10`。

1.  在`GRUB_CMDLINE_LINUX`中，删除`rhgb quiet`。保存文件。

1.  通过运行以下命令创建新文件：

```
grub2-mkconfig -o /boot/grub2/grub.cfg

```

1.  修改后的`grub.cfg`文件应该已经准备好启动了。

## 它是如何工作的...

以下是`/etc/grub.d`目录中脚本的用途的描述：

+   `00_header`：这生成`grub2.cfg`的标题，并从`/etc/default/grub`文件获取信息

+   `10_linux`：这加载菜单条目

+   `20_linux_xen`：这会查找 zen 内核并将它们添加到菜单中

+   `20_ppc_terminfo`：这在 PPC 系统上检查正确大小的终端

+   `30_os-prober`：这会在硬盘上搜索其他操作系统，以便将它们添加到启动菜单中

+   `40_custom`：这是一个模板，可用于向引导菜单添加额外的条目

+   `41_custom`：如果存在，这会从`/boot/grub/custom.cfg`中读取信息

+   `README`：这是一个包含其他有用信息的文件

## 还有更多...

以下是操作系统中可用的 GRUB 2 命令的部分列表：

+   `grub2-editenv`：这编辑 GRUB 环境块

+   `grub2-fstest`：这是一个用于 GRUB 文件系统驱动程序的调试工具

+   `grub2-kbdcomp`：这将生成一个 GRUB 键盘布局文件

+   `grub2-menulst2cfg`：这将把传统的`menu.lst`转换成`grub.cfg`

+   `grub2-mkfont`：这将创建 GRUB 字体文件

+   `grub2-mkimage`：这将创建一个可引导的 GRUB 镜像

+   `grub2-mklayout`：这将生成一个 GRUB 键盘布局文件

+   `grub2-mkpasswd-pbkdf2`：这将为 GRUB 生成一个哈希密码

+   `grub2-mkrelpath`：这将使系统路径相对于其根目录

+   `grub2-mkrescue`：这将创建一个 GRUB 救援镜像

+   `grub2-mkstandalone`：这将创建基于内存磁盘的 GRUB 镜像

+   `grub2-script-check`：这将检查`grub.cfg`的语法错误

+   `grub2-bios-setup`：这将设置设备使用 GRUB 引导

+   `grub2-install`：这将 GRUB 安装到设备上

+   `grub2-mkconfig`：这将生成一个 GRUB 配置文件

+   `grub2-mknetdir`：这将准备一个 GRUB 网络引导目录

+   `grub2-ofpathname`：这将为设备查找 OpenBOOT 路径

+   `grub2-probe`：这将探测 GRUB 的设备信息

+   `grub2-reboot`：这将设置 GRUB 的默认引导项，仅用于下一次引导

+   `grub2-set-default`：这将设置保存的默认 GRUB 引导项

+   `grub2-sparc64-setup`：这将设置设备使用 GRUB 引导

要了解更多关于 GRUB 2 的信息，请访问官方网页[`www.gnu.org/software/grub/grub.html`](http://www.gnu.org/software/grub/grub.html)。


# 附录 A：Linux 最佳实践

在本附录中，我们将涵盖以下主题：

+   超级用户与普通用户

+   运行图形用户界面

+   创建、验证和存储备份

+   权限和您的身份

+   实时备份

+   环境变量和 shell

+   最佳环境

+   使用和监控 UPS

+   复制文件时要小心

+   验证存档文件并使用校验和

+   防火墙、路由器设置和安全性

+   如果发现入侵应该怎么办

+   文件名中的空格

+   使用脚本和别名节省时间和精力

+   使用 scp 和 ssh 进行自动身份验证

+   保存历史记录和截图

+   驱动器上的空间

+   对新想法持开放态度

# 介绍

有许多事情可以让您充分利用 Linux 系统。常识告诉我们，在计算机上执行特定任务有很多方法。这是正确的，但实际上通常只有一种好的方法来完成某件事。诀窍在于要开放思想，并在好事发生时看到好处。

# 超级用户与普通用户

作为 root 用户和普通用户运行主要取决于您所处的环境。如果每个人都有自己的工作站，并且负责设置它，那么对您来说，作为 root 运行可能非常自然（尤其是如果您不犯错误）。但是，如果您在银行或其他可能因打字错误而导致数百万美元账户被清空的情况下工作，那么作为 root 显然是不明智的。在这些情况下，假设您有权限，只有在必要时才切换到 root，并且只执行所需的任务。如果已正确配置，还可以使用 sudo。有关 sudo 的更多信息，请参见第五章，“权限、访问和安全性”。

还要记住的一件事是，您作为 root 运行时的舒适程度。如果您容易出错或紧张，并且/或者过去曾因作为 root 而造成严重损害，那么显然在这种情况下需要非常小心。另一方面，如果您一直作为 root 运行并且从未犯过错误，那就太好了。这肯定更有效率。

特别提示给系统管理员：我在不止一个场合看到过这种情况，所以在这里提一下。这适用于新手和经验丰富的系统管理员。您（也许还有您的经理）通常是系统上唯一具有 root 权限的人。这听起来是个好主意，对吧？这样可以避免有人犯错误导致整个项目崩溃。而且，成为负责人感觉很好。当别人需要更改时，他们会来找您，而您也很乐意帮忙。然后他们再来，再来，再来。在某个时刻，您意识到如果不处理这些请求，就无法完成任何工作，而他们如果没有您在身边也无法完成工作。所以您尝试设置 sudo。现在情况更糟了；每次您认为已经设置好处理任何事情时，如果再次失败，有人可能会再次来找您。那么您该怎么办呢？

您可能可以为选定的用户提供 root 访问权限。凭直觉行事。例如，观察个别用户的打字方式。他们在使用命令行时感到舒适吗？他们打字是否有权威性，还是对机器感到害怕？如果某个特定用户一直使用图形用户界面执行在命令行上更有效的任务，那么我会将其视为一个强烈的警告信号。

随着时间的推移，您将对谁可以信任 root 访问权限有所了解，并能够授予他们访问权限。当然，如果有人犯了错误，那也不是世界末日。他们实际上无法对整个项目造成严重损害，因为您一直在创建和验证每日备份，对吧？您可以恢复损坏并从他们那里收回 root 权限。请注意，只需要一个错误。我不会再信任那个用户拥有 root 权限。

# 运行图形用户界面

虽然我有点快速地信任我的用户拥有 root 访问权限，并且大部分时间我自己也使用 root，但我绝对不建议以这种方式运行 GUI。有些发行版甚至不允许这样做。通过以 root 身份运行 GUI，实际上你正在以 root 身份运行很多其他东西，比如你的浏览器和邮件程序。这绝对不是一个好主意。

以下是我在 Linux 或 UNIX 系统上的首选环境。我使用 Fedora，但这些想法应该适用于大多数其他发行版。安装系统后，我做的第一件事之一是更改系统，使得机器以命令行模式而不是图形界面启动。这样，如果发生图形问题，诊断和纠正就容易得多。我还可以选择通过运行适当的`startx`类型命令来启动哪个图形界面。在命令提示符下，我以普通用户或访客用户身份登录。在我的 Fedora 14 系统上，我然后运行`startx`，这将启动 Gnome 2。

在图形界面完全启动后，我打开一个终端会话并运行`su`到 root。我检查确保机器可以 ping 通，并通常进行一些其他的合理性检查。如果一切正常，我然后运行我的`jset`脚本。它执行一些桌面定制，比如将终端窗口打开到它们正确的目录，并提醒我要运行什么命令（我写了很多程序，所以真的需要这个）。它还会挂载我的 USB 设备，或者在出现问题时警告我。然后我将终端会话定位到我想要的位置。现在我可以开始工作了。

以下是一个类似于我在启动后用来设置我的桌面的脚本：

```
#!/bin/sh
# last update 6/9/2013 (rebooted)

echo percentused - run go
cd /lewis/java/percentused
xterm +sb -title Xterm    -geom 80x20 &

echo apcupsd - run go
cd /lewis/java/apc
xterm +sb -title Xterm    -geom 80x20 &

echo jtail - run jtail
cd /lewis/jtail-f/jtail
xterm +sb -title jtail -geom 137x30   &

echo jsecure - run jsecure
cd /lewis/jtail-f/jsecure
xterm +sb -title jtail -geom 125x33   &

echo ping - run loop1
cd /lewis/ping
xterm +sb -title ping  -geom 86x8 &

echo runbackup1 - run runbackup1
cd /lewis/backup
xterm +sb -title runbackup1 -geom 65x21 &

echo jwho - run jwho
cd /lewis/jwho
xterm +sb -title jwho  -geom 65x8  &

# mount usb stick
mount /dev/sdg1 /usb
# mount Iomega external drive
mount /dev/sdf1 /megadrive 

```

# 创建、验证和存储备份

我无法强调创建系统备份的重要性有多大。至少，将您的个人和业务数据以及配置文件复制到安全的地方。有些人甚至备份操作系统本身。无论您决定做什么，都要制定计划并坚持下去。正如第八章中所提到的，*使用脚本*，现在是设计和使用脚本的好时机。如果需要，使用`crontab`自动执行定期备份。

`tar`命令非常适合备份整个目录。请注意，它也会获取任何隐藏文件。如果需要，您可以排除特定目录，并且可以使用`tar`执行其他一些操作。以下是类似于我用来备份`/home/guest1`目录的命令。

### 提示

`tsback1`是一个包含要从中开始的数字的文本文件。

```
cat tsback1
0

```

以下是脚本的开始：

```
 cd /home
 NUM=`cat tsback1`        # get the next number to use
 tar -cvzf /megadrive/backups/backup$NUM.gz --exclude=Cache  --exclude=.cache --exclude=.thumbnails  guest1

```

请记住将要备份的目录作为行中的最后一项。首先更改`/home`目录，因为对于`tar`，您希望在要备份的子目录的父目录中。下一行将`NUM`变量设置为要使用的下一个变量。最后一行直接在我的 USB 外部驱动器中的适当目录中创建`tar`文件。

我在创建备份时尝试非常小心。我实际用来备份东西的脚本还做了很多其他事情。例如，它会检查我的 USB 外部驱动器是否真的存在，并且可以被写入（它还应该检查驱动器上是否有足够的可用空间，这是我的 TODO 之一）。如果代码确定驱动器不存在或发生其他错误，就会发出非常响亮和讨厌的警报。如果我在 5 分钟内没有回应这个警报，就会向我的手机发送电子邮件。这对于偏执狂来说怎么样？

备份是很好的。但是，如果备份无法使用，那就没有多大用处。因此，定期验证备份是明智的。多久验证一次取决于您和您的舒适水平。我的脚本定期将备份文件复制到另一台机器，然后解压并运行一些测试。如果有任何不对劲的地方，就会发出另一个警报。所有这些都是在脚本中自动完成的。

好了，我们现在正在进行备份和验证。那么存储呢？假设你已经把一切都搞定了，所有的文件都被复制和验证了，它们都位于同一个地方，比如你的家或办公室。然后发生了一些不可言喻的事情，比如火灾或盗窃。我同意，这种事情发生的可能性非常低，但它仍然可能发生。至少我不想尝试自 1982 年以来编写的百万行代码，所以我在各个地方都有备份，包括外部存储。在我工作过的一些公司中，文件被复制到磁带、CD 和/或硬盘上，并存放在一个防火的步入式保险柜中。非常好的主意。

# 权限和你的身份

这主要涉及系统管理员。作为系统管理员，你可能会大部分时间以 root 用户的身份进行工作。你设置访客账户和配额，甚至可能创建脚本等等。有时很容易忘记你的用户没有 root 权限。

记住这一点，一定要从用户的角度检查你的添加和更改。用`su`成为那个用户，确保你可以正常访问一切。这将为你节省很多时间，甚至可能避免尴尬，如果你在用户之前发现了问题。

# 实时备份

在编辑脚本和其他文件时，最好做一些编号的备份。没有什么比让一些东西工作，然后在做了一些更改后出现问题，然后不能快速地让它重新工作更令人沮丧的了。有了编号的备份，你总是可以回到之前工作的版本，然后使用`diff`找到错误。我确实是以最艰难的方式学到了这一点。

以下是我为本书的用户编写的备份脚本（我通常使用的是用 C 编写的）。它的名字是`mkbak`：

```
#!/bin/sh
# mkbak script to create backup files
if [ "$1" = "" ] ; then
 echo "Usage: mkbak filename(s)"
 echo "Creates numbered backup file(s) in the current directory."
 exit
fi
for i in $* ; do
 if [ ! -f $i ] ; then
 echo File $i not found.
 continue
 fi

 num=1
 while [ 1 ]
 do
 ibak=bak-$num.$i
 if [ -f $ibak ] ; then
 num=`expr $num + 1`
 else
 break
 fi
 done
 cp $i $ibak
 rc=$?
 if [ $rc -eq 0 ] ; then
 echo File $i copied to $ibak
 else
 echo "An error has occurred in the cp command, rc: $rc"
 fi
done

```

这个脚本是免费的，但有一些限制。它不能处理带空格的文件名，只能处理当前目录中的文件。请注意，你可以先`cd`到你想要的目录，然后再运行它。

以下是我用来备份当前正在工作的书籍文件的脚本：

```
#!/bin/sh
# b1 script to copy book file
# Date 1/22/2013
FN=startA1.txt                    # name of file to back up
STARTDIR=`pwd`                    # remember the starting directory
cp $FN /usb/book                  # copy to USB stick
cd /usb/book                      # cd to it
mkbak $FN                         # make the numbered backup

cd $STARTDIR                      # go back to the starting directory
cp $FN /megadrive/book            # copy to USB external drive
cd /megadrive/book                # cd to it
mkbak $FN                         # make the numbered backup

cd $STARTDIR                      # go back to the starting directory
sum $FN /usb/book/$FN /megadrive/book/$FN     # use sum to check
scp $FN $B2:/temp                 # copy to my other machine
ssh $B2 /usr/bin/sum /temp/$FN       # check the copy

```

在编辑文件（`FN`变量）时，我会不时手动运行这个脚本，通常是在做了很多更改之后，以及在我起身休息之前。

# 环境变量和 shell

在系统管理中经常遇到的一个问题是监控多台机器。同时打开 5 或 6 个`ssh`会话并不罕见，如果有多个显示器的话，会更多。知道哪个会话在哪台机器上运行是至关重要的，因为在错误的机器上输入正确的命令可能会造成灾难。因此，出于这个原因和其他原因，我建议在登录到远程机器时使用自定义的`PS1`变量。

这在第一章中提到，*使用终端/命令行*，在讨论环境变量时。以下是我在运行 Fedora 17 的机器上`PS1`变量的样子：

```
Big2 /temp/linuxbook/chapA # echo $PS1
Big2 \w #
Big2 /temp/linuxbook/chapA #

```

简单，而不会太混乱。当我登录到另一台机器时，`PS1`的样子如下：

```
BIG4 BIG4 BIG4 BIG4 BIG4 BIG4 BIG4 BIG4 /temp # echo $PS1
BIG4 BIG4 BIG4 BIG4 BIG4 BIG4 BIG4 BIG4 \w #
BIG4 BIG4 BIG4 BIG4 BIG4 BIG4 BIG4 BIG4 /temp #

```

应该很难混淆它们。

当谈到环境变量时，还有一些事情需要记住。当你对`.bashrc`文件进行更改并进行源代码化时，这些更改只在该会话中可见（以及任何新打开的会话）。为了在其他现有会话中看到更改，你必须在其中也进行源代码化。如果有一种方法可以通过一个命令使更改在每个会话中可见，那将是相当酷的，然而，我不相信这是可能的。当然，有人可能会说`shutdown -r`现在可以做到。

# 最好的环境

对一个人最好的可能对另一个人不是最好的。然而，我知道当我使用一个快速的桌面系统，有足够的内存和存储空间，以及两个大显示屏时，我是最高效的。以下是我的典型设置：

在我的左侧显示器上，我放置了脚本和以下用于监控系统的程序：

+   一个用 Java 和 C 编写的磁盘空间监控程序

+   一个监视我的**不间断电源**（**UPS**）的程序，也是用 Java 和 C 编写的

+   一个每分钟一次对网络进行 ping 并记录任何故障的脚本

+   一个使用`tail -f /var/log/messages`来监控内核消息的程序

+   我的备份脚本每天凌晨 3 点运行一次。

+   一个“穷人版”入侵检测脚本（稍后详细介绍）

+   一个每天两次向我的手机发送系统状态的脚本

+   我将“计算机”和“访客”文件夹图标设置为可见并易于访问

+   任何连接到远程机器的`ssh`会话

+   还有一些其他太无聊不值得一提的东西

所有这些都设置为在所有工作区中保持可见。说到工作区，我通常有四个。我总是将相同的程序和终端会话放在相同的工作区，并且在屏幕上大致相同的位置。这样，我可以非常快速地到达想要去的地方。您是否曾经处于一个情况，您的团队即将错过重要的截止日期，而您被迫观望，因为其他人在系统上浪费了大量时间寻找或做某事？您绝对不想成为那个人。

在右侧显示器上，我进行大部分实际工作。以下是我的工作区布局方式：

+   在工作区 1 有两个终端。它们已经准备好，以防我需要立即做一些事情

+   工作区 2 通常用于程序开发。我在这里进行 C、Java 和脚本开发

+   工作区 3 是我目前正在使用自定义文本编辑器输入这本书的地方（最终将被导入到`LibreOffice`中）

+   工作区 4 是我放置我的网络邮件客户端的地方

说到浏览，我倾向于在左侧显示器上打开它们，并在与我当前工作相关的工作区中打开。这样非常快捷高效，而且在需要时也更容易剪切和粘贴。

并非所有人都有快速机器或双显示器的奢侈条件，特别是在我们的工作中，有时似乎更重要的是为了节省成本，而不是给员工提供他们需要提高生产力的条件。我能说的就是，尽力获取您需要以尽可能高效地完成工作。

# 使用和监控 UPS

在我看来，至少应该在主要工作站上使用 UPS。如果电源突然断开（或更糟糕的是，变压器故障），硬件可能会出现各种问题，更不用说数据可能会发生什么了。我意识到，使用现代日志文件系统，数据丢失是相当罕见的，但为什么要冒这个险呢？而且，我真的不喜欢重新启动。永远不喜欢。

根据您的情况，尽量购买您能负担得起的最好的 UPS。您需要一个能够长时间运行系统并为您的显示器、调制解调器、路由器和外部驱动器提供电源的 UPS。这样，如果电源短暂中断，您就不会丢失任何数据，并且不必等待所有设备重新启动。

今天有许多不同品牌的 UPS 可用。我对**美国电源转换**（**APC**）设备有些偏爱。我有几个，它们在 Linux 上运行良好。确保购买一个带有电话连接器到 USB 端口的 UPS，因为旧式串行端口的设备无法正常工作。

`apcupsd`守护程序可用于监控 UPS。如果您的发行版尚未安装它，可以安装该软件包。

+   如果使用 Fedora，请运行`yum -y install apcupsd`（根据需要替换您的软件包安装程序）

+   在`/etc/apcupsd/apccontrol`文件中注释掉`WALL`语句，以防止烦人的消息被广播到每个终端

+   运行`apcaccess status`来查询 UPS

你可以用`apcupsd`做更多的事情，更多信息请查看它的网站[`www.apcupsd.com`](http://www.apcupsd.com)。这也列出了一些可能与 Linux 不兼容的 UPS 设备。

还有一件事，你可能想要使用 UPS 的自动关机功能。它可以在停电时间过长时自动关闭你的机器。大多数设备允许你设置在关闭之前运行的时间。请记住，UPS 在电池上运行的时间越长，它们的寿命就会越短。

# 在复制文件时要小心

在将文件复制到目录时，请确保它确实是一个目录。这种情况发生得足够频繁，以至于我不得不提到它，我必须承认我有时仍然会犯这个错误。很容易将许多文件复制到你认为是目录的地方，但实际上并不是。结果就是只有最后一个被复制的文件会存在，如果你没有保留源文件，它们可能会丢失。在复制文件之前，使用`file`命令验证目标是否真的是一个目录。

# 验证存档文件并使用校验和

经常出现的一件事是在创建将要发送给其他人或站点的`tar`或`zip`存档时，会发现未被注意到的错误。

以下是应该遵循的步骤：

1.  将文件复制到适当的目录（确保它确实是一个目录）。

1.  使用`zip`或`tar`进行压缩和创建存档。

1.  使用`tell`或`list`选项确保它看起来正确。对于 TAR，是`tar -tvzf filename.gz`，对于 ZIP，是`unzip -l filename.zip`。

1.  对你的文件运行`sum`命令，然后将文件发送到需要去的地方。

1.  如果使用`scp`，请使用`ssh`在远程系统上运行`sum`命令，如下所示：

```
ssh <user@remote-host> /usr/bin/sum filename.gz

```

1.  两个`sum`值应该匹配。

1.  如果使用电子邮件，在你的端上运行`sum`，并将结果与电子邮件一起发送。

给开发人员的一个建议；假设你正在创建一个编程项目的存档。为了确保你已经复制了它所需的每个文件，创建存档，然后将其复制到另一台机器上。像平常一样解压并构建它。如果缺少所需的文件，将会出现错误。

# 防火墙、路由器设置和安全性

防火墙在第五章中有所涉及，*权限、访问和安全*，所以这只是一个简要的回顾。如果你运行的是家庭系统并且使用一个好的路由器，`iptables`的默认设置可能已经足够了。它可能需要一些调整，例如使用扫描仪，但大部分时间你可能已经免受黑客的攻击。另一方面，如果你是一个大公司的系统管理员，`iptables`可能不够用。我会调查使用硬件入侵设备或其他方法，以确保数据和系统的安全。

强烈建议始终使用带有内置防火墙的路由器。我绝不会直接将系统连接到互联网。尽管典型的 Linux 系统可能会幸存下来，但我曾经看到 Windows 系统在不到 30 分钟内感染了病毒。

默认的路由器设置可能已经足够强大，可以防止典型的黑客入侵。为了确保，也为了了解路由器内部发生了什么，最好定期登录并检查一切。在大多数路由器上，将浏览器指向`192.168.1.1`会弹出登录界面。在大多数情况下，需要输入 ID 和密码。

`who`命令可以在 Linux 中用来显示系统上每个用户的用户名、tty、日期、时间和 IP 地址，如下面的截图所示：

![防火墙、路由器设置和安全性](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_A_01.jpg)

还有另一件事可以帮助防止入侵。拒绝`ssh`/`scp`的 root 访问是个好主意，因为黑客通常会尝试以 root 身份入侵。这可以通过编辑`/etc/ssh/sshd_config`文件来实现。找到一行写着`#PermitRootLogin yes`的地方，将其改为`PermitRootLogin no`。不要忘记去掉`#`（井号）。你还需要重新启动`sshd`。现在，任何以 root 身份登录的尝试都将失败。我已经将我所有的机器都设置成了这样，作为额外的预防措施。

最后一件事，每当有人登录（或尝试登录）到你的系统时，都会有记录。在 Fedora 上，这会记录在`/var/log/secure`文件中。你可以不时地检查这个文件，或者使用`tail -f /var/log/secure`命令来监视它。

现在是一个额外的奖励。以下是一个我用来监视对我的机器的未经授权访问的简单脚本：

```
#!/bin/sh
tput clear
echo "jwho by Lewis 10/23/2011"
numusers=`who | wc -l`
while [ 1 ]
do
 rc=`who | wc -l`       # get number of users
 if [ $rc -gt $numusers ] ; then
 echo "Someone new has logged on!!!!!!!!!!!"
 date
 who
 jalert5 &            # see below
 numusers=$rc
 elif [ $rc -lt $numusers ] ; then
 echo "Someone logged off."
 date
 numusers=$rc
 fi
 sleep 5
done

```

基本上，这个脚本每 5 秒检查一次用户数量是否发生了变化。如果增加了，`jalert5`脚本将在后台运行。它每 5 秒播放一个非常讨厌的 WAV 文件，直到我关闭它。这也会在每次打开新会话时触发，所以你可能会希望在启动后最后运行它。

# 如果发现入侵怎么办

假设你发现发生了入侵。你应该怎么办？

### 提示

这些说明适用于你的机器或你完全负责的机器。如果这发生在你工作的机器上，立即按照公司针对安全事件的任何程序进行操作。

如果怀疑发生了入侵，需要迅速采取行动。运行`who`命令或`cat /var/log/secure`并检查输出。如果看到可疑的 IP 地址，采取以下行动：

+   如果这是一台非常重要的机器，上面有关键数据，我会立即拔掉以太网线并立即关闭它。然后我会从救援介质启动，尝试确定是否发生了任何不好的事情。检查他们进入的日期和时间（从`who`命令）可能会让你知道他们可能造成了多大的破坏。

+   如果这是我的家庭系统，我会首先拔掉以太网线。然后我会运行`ps auxw`命令将系统当前的运行情况保存到文件中。我会将这个文件复制到其他机器或设备上，然后关闭系统。

通过检查`ps`输出并查看`tty`值，我可能可以确定他们正在运行的程序，如果有的话。这可能会指出他们试图通过进入系统来实现什么目的。

显然，如果有人真的进入了你的系统，他们很可能是通过猜测或某种方式确定了密码。我可能会将所有密码重置为更难破解的密码，然后告诉我的用户选择更好的密码。或者可能自己分配密码。

好吧，至少有一个人在读这篇文章时会想为什么要拔掉以太网线？为什么不只是关闭接口？因为一个狡猾的攻击者会考虑到这一点，一旦他获得了访问权限，他就会在系统上自动放置代码，以便在接口关闭时自动重新打开它。他甚至可能给它加上一个定时器，或以其他方式隐藏它。

攻击者可能有时间做各种事情。他甚至可能修改了`who`、`ps`和其他命令，使得几乎不可能从运行的系统中跟踪他所做的事情（或仍在做的事情）。考虑到这一点，你仍然需要尽快关闭系统，然后使用救援盘或等效物重新启动。需要查看的一些事情是`ps`和`who`等命令。运行`file`命令，它应该显示它们是二进制可执行文件，而不是 shell 脚本。如果它们是 shell 脚本，你可能会发现攻击者已经用`.`重命名了可执行文件，以隐藏它们，然后将它们包装在一个脚本中，以帮助掩盖他的存在。还有许多其他隐藏的方法。

# 文件名中的空格

在为自己或其他人生成文件时，不要在文件名中包含空格。这可能会在 Linux 和 UNIX 机器上引起很多问题。如果必要，使用大写字母和/或下划线。也不要使用括号或其他特殊字符。我第一次使用 Firefox 下载文件时真的很惊讶，因为它插入了括号以将其与同名文件区分开。我很感激它没有简单地覆盖原始文件，但使用括号是一个非常糟糕的主意。

# 使用脚本和别名来节省时间和精力

我在现场看到的一件事是，人们浪费时间和精力一遍又一遍地输入相同的东西。不要这样做。使用别名和脚本。不要考虑编写脚本可能需要多少时间，而是考虑通过能够一直使用它来节省多少时间。您可能还可以在以后将其合并到另一个脚本中（特别是如果一开始就写得很好）。此外，有了这些可用的东西应该有助于满足截止日期。

# 使用自动身份验证的 scp 和 ssh

按照以下步骤允许使用`ssh`/`scp`而无需输入密码。您需要是 root 用户。

1.  首先，确保客户端至少使用过`ssh`。这将创建所需的正确目录。

1.  在主机上运行`ssh-keygen -t rsa`命令。这将创建一些必要的文件。

1.  如果客户端上不存在`/root/.ssh/authorized_keys`文件，您可以运行`scp /root/.ssh/id_rsa.pub <hostname>:/root/.ssh/authorized_keys`。

1.  否则，将`id_rsa.pub`文件复制到客户端，然后将其添加到`authorized_keys`文件中（我通常将其放在底部）。

1.  现在，您应该能够在不输入密码的情况下对客户端进行`scp`和`ssh`。这真的很方便，特别是在脚本中。

您还可以将此条目添加到另一个用户帐户中。例如，我将其添加到了我的`/home/guest1/.ssh/authorized_keys`文件中。这样，我可以作为 root 从一台机器复制文件，另一台机器仍然会接受它。

# 保存历史记录和截屏

在处理计算机时，我们都必须学习新的东西。有时所涉及的步骤非常复杂，我发现实际上每一种情况下，无论我用来执行这些步骤的文档或网站都存在错误。它不完整，作者跳过了重要的步骤等等。因为这些原因和其他原因，当我（终于）让某些东西运行起来后，我会在会话中运行`history`命令并将其输出到文件中。然后我以合适的名称保存这个文件，以便以后能够找到它。

根据所需的努力程度，如果合适的话，我也可能对每个步骤进行截屏。这可以作为以后的参考，如果您必须帮助其他人完成相同的任务。或者，如果有人说服您有朝一日写一本关于它的书。

# 驱动器上的空间

在过去，硬盘空间总是不够。我们总是快用完或者用完了，试图找到增加存储空间的方法。现在，在现代社会，这可能不再是一个问题。但是，随时监视您的可用空间仍然是一个好主意。

有很多方法可以做到这一点。在我的系统上，我使用了我用 C 和 Java 编写的一个程序。它叫做“使用百分比空间”，只是在底层使用了`df -h`。您可以将`df`放入脚本中，或者不时手动检查空间。只是不要用完！填满分区是一种让您手忙脚乱的好方法，特别是如果它是系统分区。

# 接受新想法

这是我给想更好地了解 Linux 的人的最后一条建议。我经常看到在这个领域里的人们在做他们的日常工作，而且都是以同样的方式。要时刻注意如何改进你执行日常任务的方式。如果你看到一个同事做一些对你来说很奇怪的事情，不要假设他的方式是错的，你的是对的。他的方法可能比你的好得多。向他学习。另一方面，他可能*没有*更好的方法，你的可能更好。在这一点上，你可以决定是否尝试分享你的想法。我发现大多数人对此非常抵触。

不要让自己陷入“你的方式不比我的好，只是不同”的争论中。正如我之前提到的，通常只有一种正确的执行任务的方式，但大多数人并不明白这一点。尽量在你能找到的时候找到它，并且只在对方愿意接受帮助的情况下分享你的想法。


# 附录 B：寻求帮助

在本附录中，我们将涵盖以下主题：

+   使用`man`页面

+   使用`info`命令

+   命令和`Usage`部分

+   本地文档目录

+   浏览网页以寻求帮助

+   发行说明

+   Linux 用户组

+   Internet Relay Chat（IRC）

# 介绍

在 Linux 上寻求帮助的地方有很多。实际上，有很多可用的信息；事实上，在某些情况下太多了。很难从好东西中过滤出噪音。在这里，我们试图向您展示如何快速有效地获得所需的内容。

# 使用 man 页面

`man`实用程序是本地参考手册的接口。它用于快速查找有关程序、实用程序、函数和其他主题的信息。`man`实用程序将接受几个选项；但是，通常的调用只是`man page`，其中 page 实际上是指一个主题。您甚至可以单独运行`man`来学习如何使用它。

以下是`man man`命令的屏幕截图：

![使用 man 页面](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_B_01.jpg)

在页面上运行`man`显示感兴趣的主题。空格键用于向下翻页，*Q*用于退出。页面（主题）以更或多或少标准的顺序呈现，可能的部分名称有：`NAME`，`SYNOPSIS`，`CONFIGURATION`，`DESCRIPTION`，`EXAMPLES`，`OVERVIEW`，`DEFAULTS`，`OPTIONS`，`EXIT STATUS`，`RETURN VALUE`，`ENVIRONMENT`，`FILES`，`VERSIONS`，`CONFORMING TO`，`NOTES`，`BUGS`，`AUTHORS`，`HISTORY`和`SEE ALSO`。

`man`显示找到的第一页，即使其他部分中有更多页面。例如，假设您正在寻找有关如何在 C 程序中编写`readlink`函数的信息。您可以尝试以下命令：

```
man readlink

```

它会打开一个页面，但是命令是`readlink`而不是 C 函数。为什么？因为它显示第一页，除非您在页面之前指定部分编号。好吧，您怎么知道那是什么？您可以以以下方式使用`man`选项`-a`运行`man`：

```
man -a readlink

```

这将像以前一样提出`readlink`命令。现在按*Q*退出。页面消失了，但是`man`会话显示如下内容：

```
Big4 /lewis/Fedora/17 # man -a readlink
--Man-- next: readlink(2) [ view (return) | skip (Ctrl-D) | quit (Ctrl-C) ]

```

这给了您一个选择：按*Enter*将显示下一页（主题），*Ctrl* + *D*将跳转到下一个主题，*Ctrl* + *C*将结束`man`会话。当您在最后一个主题上按*Q*时，`man`将像以前一样正常终止。

那么，如果您已经知道要直接加载第三部分的页面，该怎么办？您可以以以下方式指定它：

```
man 3 readlink

```

这将跳过前两个，直接进入 POSIX 程序员手册中的`readlink`页面。

以下是各节编号及其名称的列表：

+   1：可执行程序或 shell 命令

+   2：系统调用（内核提供的函数）

+   3：库调用（程序库中的函数）

+   4：特殊文件（通常在`/dev`中找到）

+   5：文件格式和约定（例如，`/etc/passwd`）

+   6：游戏

+   7：其他（包括宏包和约定），例如，man(7)和 groff(7)

+   8：系统管理命令

+   9：内核例程

本地参考手册可以是获取信息的重要来源。它们包含有关 Linux 系统中几乎所有内容的大量数据。不幸的是，它们也有一些缺点。大多数写得很好并且有意义。有些则相当糟糕。当发生这种情况时，还有其他地方可以寻求帮助。

# 使用 info 命令

除了 man 页面外，大多数 Linux 系统还有`Info`文档。这些是通过使用`info`程序访问的。一般来说，`Info`文档提供的数据往往比典型的`man`页面更详细和更有信息量。

像`man`一样，您可以单独运行 info：

```
info info

```

这是如何使用`info`的介绍。最后一段说**如果对 info 不熟悉，现在输入'h'。这将带你进入一个程序化的指令序列**。如果你有兴趣学习如何充分利用`info`，我建议在这里按*H*来运行教程。

以下是运行`info info`然后按*H*的屏幕截图：

![使用 info 命令](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_B_02.jpg)

# 命令和用法部分

Linux 中的大多数命令都有一个`Usage`部分，可以通过使用`--help`选项来显示。典型的例子有`cat`，`cut`，`ifconfig`，`bash`，`rm`等。

以下是`rm --help`的屏幕截图：

![命令和用法部分](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_B_03.jpg)

请注意，一般来说，`Usage`部分并不真的意在教会某人很多关于一个命令。它真的是用来提醒用户参数是什么，以及命令的一般格式。

请注意，一些命令，特别是那些需要参数才能完成某些操作的命令，只需调用而不提供参数就会显示它们的用法信息。

以下是运行`awk`命令而不带参数的屏幕截图：

![命令和用法部分](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_B_04.jpg)

# 本地文档目录

大多数完整的 Linux 发行版都有包含各种主题文档的目录。根据使用的发行版不同，布局可能略有不同，但在大多数情况下，文件位于`/usr/share/doc`目录中。以下是从 Fedora 14 中`/usr/share/doc`目录的部分列表：

+   `/usr/share/doc/BackupPC-3.1.0`

+   `/usr/share/doc/ConsoleKit-0.4.2`

+   `/usr/share/doc/Django-1.2.3`

+   `/usr/share/doc/GConf2-2.31.91`

+   `/usr/share/doc/GeoIP-1.4.7`

+   `/usr/share/doc/GitPython-0.2.0`

+   `/usr/share/doc/HTML`

+   `/usr/share/doc/ImageMagick-6.6.4.1`

+   `/usr/share/doc/ModemManager-0.4`

+   `/usr/share/doc/MySQL-python-1.2.3`

+   `/usr/share/doc/NetworkManager-0.8.1`

+   `/usr/share/doc/abrt-1.1.13`

+   `/usr/share/doc/ant-1.7.1`

+   `/usr/share/doc/apcupsd-3.14.8`

+   `/usr/share/doc/doxygen-1.7.1`

+   `/usr/share/doc/ethtool-2.6.38`

+   `/usr/share/doc/fedora-release-14`

+   `/usr/share/doc/gcc-4.5.1`

+   `/usr/share/doc/gcc-c++-4.5.1`

+   `/usr/share/doc/gimp-2.6.11`

+   `/usr/share/doc/git-1.7.3.1`

+   `/usr/share/doc/gnome-desktop-2.32.0`

+   `/usr/share/doc/gnuchess-5.07`

+   `/usr/share/doc/httpd-2.2.16`

+   `/usr/share/doc/httpd-tools-2.2.16`

+   `/usr/share/doc/java-1.6.0-openjdk-1.6.0.0`

+   `/usr/share/doc/java-1.6.0-openjdk-devel-1.6.0.0`

+   `/usr/share/doc/kaffeine-1.1`

+   `/usr/share/doc/mailx-12.4`

+   `/usr/share/doc/make-3.82`

+   `/usr/share/doc/man-db-2.5.7`

+   `/usr/share/doc/man-pages-3.25`

还有一个文档查看器/浏览器，通常通过文件夹对话框访问。例如，如果你打开文件管理器并转到`/usr/share/doc`下的一个目录，你会看到许多文件。点击`README`文件将会带出更多关于你系统上特定程序的信息。还可能有其他可读的文件，比如`CONTENT`，`AUTHOR`，`MAINTAINERS`，`INSTALLATION`等等。

# 浏览网页寻找帮助

使用互联网肯定是在 Linux 任务上寻找帮助的好方法。在许多情况下，它甚至可能比依赖本地来源更好，因为自从文档上次放在你的系统上以来可能已经发生了更新。当我需要使用网络查找某些东西时，我直接去谷歌高级搜索。

以下是[`www.google.com/advanced_search`](http://www.google.com/advanced_search)的屏幕截图，其中一些字段已经填写：

![浏览网页寻找帮助](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_B_05.jpg)

使用这种搜索方法很快，你可以使用这些字段来缩小你要查找的范围。

请记住，互联网上有很多信息。其中一些是准确的，正是您所寻找的。然而，在许多情况下，信息是不正确的。回答问题的人可能会表现得自己是该主题的专家，而实际上并非如此。许多人在提出解决方案之前也不总是检查他们的解决方案。在尝试互联网上给出的解决方案时要注意这一点。

这种情况的反面也是正确的。如果您想帮助他人，那绝对是很好的。但是，在发送答复之前，请考虑并测试您希望提供的任何解决方案的准确性。

# 发行说明

了解有关您的 Linux 发行版的更多信息的一个很好的方法是查看其发行说明。这些通常包含以下信息：

+   它们记录了自上次发布以来所做的更改。通常分为特定用户的部分，如系统管理员、桌面用户、开发人员等。请注意，在某些发行版中，“技术说明”文档中提供了更多信息。

+   它们详细说明了运行“发行版”所需的最低硬件要求/架构。特别关注内存、图形和视频问题。

+   它们提供了重点介绍引导和特殊或不寻常设置的安装说明。

+   它们提供了可以安装的可能桌面环境的列表，通常附有安装步骤。这是一个非常重要的部分，因为使用设计不佳和/或有错误的桌面会影响您的生产力。

+   它们解释了新功能、功能和程序的添加情况。有时会跟上添加背后的原因，以及替换了哪个程序。

+   它们包括一个列出被弃用（移除）的程序和功能的列表。

+   它们指出了在哪里获取额外帮助的指针，如网站和聊天室。

+   它们包含了“发行版”中仍然存在的已知错误和问题的列表，以及可能的解决方法的信息。在提交错误报告之前，始终查阅此列表。

+   它们提供了如何就发行版和发行说明提供反馈意见的说明，以及您希望添加/更改的任何功能。

以下是来自[http://docs.fedoraproject.org/en-US/Fedora/19/html/Release_Notes/index.html]的 Fedora 19 发行说明的截图：

![发行说明](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_B_06.jpg)

以下是来自[https://wiki.ubuntu.com/RaringRingtail/ReleaseNotes]的 Ubuntu 13.04 发行说明的链接：

![发行说明](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_B_07.jpg)

以下截图是来自[http://www.debian.org/releases/stable/amd64/release-notes]的 Debian 7.0（Wheezy）：

![发行说明](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_B_08.jpg)

发行说明非常值得一读。在安装新发行版之前、期间和之后，我都会浏览它们。这确保我充分利用了我的发行版，告诉我新功能，并帮助我避免花费过多时间和精力来解决已知的错误或问题。

# Linux 用户组

另一个很好的寻求帮助的地方是您当地的用户组。要找到您附近的用户组，请尝试在 Linux 用户组上进行高级 Google 搜索，然后输入您的城市（如果需要，还有州）。您应该会看到一些选项。请注意，大多数只需要有效的电子邮件地址即可订阅该组。一般来说，要提问，您只需像平常一样撰写问题，然后将其发送到组的电子邮件地址。通常，对该领域有了解的人通常会迅速提供帮助，并通过电子邮件向组回复可能的答案。在大多数情况下，您还可以搜索组的存档以查找信息。

我通过在**Central Texas Linux Users Group**（**CTLUG**）上提问找到了许多困难问题的答案。

以下是[`ctlug.org/`](http://ctlug.org/)的 CTLUG 网站的屏幕截图：

![Linux users' groups](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_B_09.jpg)

# Internet Relay Chat (IRC)

使用 IRC 是了解您感兴趣的各种主题的好方法。这也是一个很好的寻求帮助的地方。经常访问这些聊天室的人通过加入与他们感兴趣并且了解的主题相关的频道来实现。这也都是实时进行的，无需等待电子邮件回复。您只需要一个 IRC 客户端、一个服务器和一个组（频道）来加入，（在大多数情况下）就可以开始了。有很多不同的 IRC 客户端。其中一些是文本模式（命令行），一些是基于 GUI 的。

以下是[`www.irchelp.org/irchelp/clients/unix/`](http://www.irchelp.org/irchelp/clients/unix/)的屏幕截图，这是一个展示 Linux 和 Unix 的不同 IRC 客户端的网站：

![Internet Relay Chat (IRC)](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_B_10.jpg)

如果您是 IRC 的新手，以下是一些指针，可以帮助您入门。我之前没有安装过 IRC 客户端，所以首先安装了`irssi`在我的 Fedora 17 机器上，通过以 root 身份运行`yum`命令：

```
yum -y install irssi

```

这很顺利。

以下是 Fedora 17 上`irssi –help`的屏幕截图：

![Internet Relay Chat (IRC)](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-util-cb/img/3008OS_B_11.jpg)

这个程序允许进行相当多的自定义。我的系统上的默认配置包含在`/home/<user>/.irssi/config`文件中。您可以使用先前的设置来覆盖这些设置。现在，让我们先简单运行它，看看它是什么样子。

1.  首先运行`irssi`。它应该会带出一个文本模式屏幕，并向您显示欢迎消息，因为这是您第一次进入。

1.  连接到服务器。在这个例子中，我们将使用 freenode。运行：

```
/connect irc.freenode.net

```

1.  您应该看到另一条欢迎类型的消息。现在我们需要一个频道。在这个例子中，运行`/join #chat`命令（不要忘记`#`符号）。

1.  您现在应该通过`#chat`频道连接到 freenode，并能够与其他用户聊天。

请注意，`irssi`确实需要一点时间来适应。底部是一个状态屏幕。您可能会看到类似**[ Act: 2]**或等效的内容。这表示另一个窗口中有新的文本，您可以通过按下*Alt*键，然后按数字来访问该窗口。因此，*Alt* + *2*将带您到下一个屏幕。

您在其中输入的任何内容，如果没有以`/`符号开头，都将发送给当前组中的所有人。请记住这是一个公共论坛；请小心您说的话，并遵循指示。还要注意不要在聊天会话中透露个人信息。

有很多网站上包含有关 IRC 的信息。以下是我找到的一些网站：

+   [`www.irchelp.org/`](http://www.irchelp.org/)

+   [`www.linux.org/article/view/irssi-for-beginners-2012`](http://www.linux.org/article/view/irssi-for-beginners-2012)

+   [`www.tldp.org/LDP/sag/html/irc.html`](http://www.tldp.org/LDP/sag/html/irc.html)

+   [`wiki.archlinux.org/index.php/IRC_Channel`](https://wiki.archlinux.org/index.php/IRC_Channel)

有很多 Linux 频道可供选择，很难把它们列成一份清单。有些需要认证，而有些则可以立即开始聊天。找到它们的最佳方法是在互联网上搜索你需要帮助的主题，并包括短语 IRC。连接到适当的服务器，加入频道，遵循可能存在的任何特殊指示，并享受聊天乐趣！
