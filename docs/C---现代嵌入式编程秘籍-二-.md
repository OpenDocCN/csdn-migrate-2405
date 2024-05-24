# C++ 现代嵌入式编程秘籍（二）

> 原文：[`annas-archive.org/md5/5f729908f617ac4c3bf4b93d739754a8`](https://annas-archive.org/md5/5f729908f617ac4c3bf4b93d739754a8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：处理中断

嵌入式应用程序的主要任务之一是与外部硬件外设通信。使用输出端口向外设发送数据很容易理解。但是，当涉及到读取时，情况变得更加复杂。

嵌入式开发人员必须知道何时可以读取数据。由于外围设备外部于处理器，这可能发生在任何时刻。

在本章中，我们将学习什么是中断以及如何处理中断。在以 8051 为目标平台的 8 位微控制器上，我们将学习以下主题：

+   如何实现基本中断处理

+   如何使用定时器中断从 MCU 的输出引脚生成信号

+   如何使用中断来计算 MCU 外部引脚上的事件

+   如何使用中断在串行通道上进行通信

通过完成以下示例，我们将学习这些主题：

+   实现中断服务例程

+   使用 8 位自动重装模式生成 5 kHz 方波信号

+   使用定时器 1 作为事件计数器来计算 1 Hz 脉冲

+   串行接收和发送数据

了解如何处理中断的核心概念将帮助您实现响应灵敏且节能的嵌入式应用程序。

然而，在此之前，我们将获取一些背景知识。

# 数据轮询

从外部源等待数据的第一种方法称为**轮询**。应用程序周期性地查询外部设备的输入端口，以检查是否有新数据。这种方法易于实现，但有显著的缺点。

首先，它浪费处理器资源。大多数轮询调用报告数据尚不可用，我们需要继续等待。由于这些调用不会导致某些数据处理，这是对计算资源的浪费。此外，轮询间隔应该足够短，以便快速响应外部事件。开发人员应该在处理器功率的有效利用和响应时间之间寻求折衷。

其次，它使程序的逻辑变得复杂。如果程序应该每 5 毫秒轮询一次事件，例如，那么它的任何子程序都不应该超过 5 毫秒。结果，开发人员人为地将代码分成更小的块，并组织它们之间的复杂切换，以允许轮询。

# 中断服务例程

中断是轮询的一种替代方法。一旦外部设备有新数据，它会在处理器中触发一个称为**中断**的事件。顾名思义，它会中断正常的执行指令流程。处理器保存其当前状态，并开始从不同的地址执行指令，直到遇到从中断返回的指令。然后，它读取保存的状态以继续执行从中断时刻开始的指令流。这种替代的指令序列称为**中断服务例程**（**ISR**）。

每个处理器都定义了自己的一组指令和约定来处理中断；然而，在处理中断时，它们都使用相同的一般方法：

+   中断由数字标识，从 0 开始。这些数字映射到硬件**中断请求线**（**IRQ**），这些线物理上对应于特定的处理器引脚。

+   当 IRQ 线被激活时，处理器使用其编号作为中断向量数组中的偏移量，以定位中断服务例程的地址。中断向量数组存储在内存中的固定地址上。

+   开发人员可以通过更新中断向量数组中的条目来定义或重新定义 ISR。

+   处理器可以被编程以启用或禁用中断，无论是针对特定的 IRQ 线还是一次性禁用所有中断。当中断被禁用时，处理器不会调用相应的 ISR，尽管可以读取 IRQ 线的状态。

+   IRQ 线可以编程触发中断，取决于物理引脚上的信号。这可以是信号的低电平、高电平，或者边沿（即从低到高或从高到低的过渡）。

# ISR 的一般考虑

这种方法不会浪费处理器资源进行轮询，并且由于中断处理是在硬件级别执行的，因此提供了非常短的反应时间。然而，开发人员应该注意其具体情况，以避免未来出现关键或难以检测的问题。

首先，同时处理多个中断，或者在处理前一个中断的同时响应相同的中断，是很难实现的。这就是为什么 ISR 在中断被禁用时执行。这可以防止 ISR 被另一个中断打断，但也意味着待处理中断的反应时间可能会更长。更糟糕的是，如果中断不及时重新启用，这可能会导致数据或事件丢失。

为了避免这种情况，所有 ISR 都被编写为简短的。它们只做最少量的工作，以从设备中读取或确认数据。复杂的数据分析和处理是在 ISR 之外进行的。

# 8051 微控制器中断

8051 微控制器支持六个中断源-复位、两个硬件中断、两个定时器中断和一个串行通信中断：

| **中断号** | **描述** | **字节偏移** |
| --- | --- | --- |
| | 复位 | 0 |
| 0 | 外部中断 INT0 | 3 |
| 1 | 定时器 0（TF0） | 11 |
| 2 | 外部中断 INT1 | 19 |
| 3 | 定时器 1（TF1） | 27 |
| 4 | 串行 | 36 |

中断向量数组位于地址 0 处；除了复位之外，每个条目的大小为 8 字节。虽然最小的 ISR 可以适应 8 字节，但通常，条目包含将执行重定向到实际 ISR 的代码，该 ISR 位于其他地方。

复位入口是特殊的。它由复位信号激活，并立即跳转到主程序所在的地址。

8051 定义了一个称为**中断使能**（**EA**）的特殊寄存器，用于启用和禁用中断。它的 8 位分配如下：

| **位** | **名称** | **含义** |
| --- | --- | --- |
| 0 | EX0 | 外部中断 0 |
| 1 | ET0 | 定时器 0 中断 |
| 2 | EX1 | 外部中断 1 |
| 3 | ET1 | 定时器 1 中断 |
| 4 | ES | 串口中断 |
| 5 | - | 未使用 |
| 6 | - | 未使用 |
| 7 | EA | 全局中断控制 |

将这些位设置为 1 会启用相应的中断，设置为 0 会禁用它们。EA 位启用或禁用所有中断。

# 实现中断服务例程

在这个配方中，我们将学习如何为 8051 微控制器定义中断服务例程。

# 如何做...

按照以下步骤完成这个配方：

1.  切换到我们在第二章中设置的构建系统，*设置环境*。

1.  确保安装了 8051 仿真器：

```cpp
# apt install -y mcu8051ide
```

1.  启动`mcu8051ide`并创建一个名为`Test`的新项目。

1.  创建一个名为`test.c`的新文件，并将以下代码片段放入其中。这会为每个定时器中断增加一个内部`counter`：

```cpp
#include<mcs51reg.h> 

volatile int Counter = 0;
void timer0_ISR (void) __interrupt(1) /*interrupt no. 1 for Timer0 */
{ 

  Counter++;
} 

void main(void) 
{ 
  TMOD = 0x03; 
  TH0 = 0x0; 
  TL0 = 0x0; 
  ET0 = 1; 
  TR0 = 1;
  EA = 1;
  while (1); /* do nothing */ 
} 
```

1.  选择工具|编译来构建代码。消息窗口将显示以下输出：

```cpp
Starting compiler ...

cd "/home/dev"
sdcc -mmcs51 --iram-size 128 --xram-size 0 --code-size 4096 --nooverlay --noinduction --verbose --debug -V --std-sdcc89 --model-small "test.c"
sdcc: Calling preprocessor...
+ /usr/bin/sdcpp -nostdinc -Wall -obj-ext=.rel -D__SDCC_NOOVERLAY -DSDCC_NOOVERLAY -D__SDCC_MODEL_SMALL -DSDCC_MODEL_SMALL -D__SDCC_FLOAT_REENT -DSDCC_FLOAT_REENT -D__SDCC=3_4_0 -DSDCC=340 -D__SDCC_REVISION=8981 -DSDCC_REVISION=8981 -D__SDCC_mcs51 -DSDCC_mcs51 -D__mcs51 -D__STDC_NO_COMPLEX__ -D__STDC_NO_THREADS__ -D__STDC_NO_ATOMICS__ -D__STDC_NO_VLA__ -isystem /usr/bin/../share/sdcc/include/mcs51 -isystem /usr/share/sdcc/include/mcs51 -isystem /usr/bin/../share/sdcc/include -isystem /usr/share/sdcc/include test.c
sdcc: Generating code...
sdcc: Calling assembler...
+ /usr/bin/sdas8051 -plosgffwy test.rel test.asm
sdcc: Calling linker...
sdcc: Calling linker...
+ /usr/bin/sdld -nf test.lk

Compilation successful
```

1.  选择模拟器|启动/关闭菜单项以激活模拟器。

1.  选择模拟器|动画以慢速模式运行程序。

1.  切换到 C 变量面板，并向下滚动，直到显示 Counter 变量。

1.  观察它随时间的增长：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/6bfb07eb-bdc2-4be0-a095-90ce3bda6141.png)

如您所见，`Counter`变量的值字段现在是 74。

# 它是如何工作的...

对于我们的示例应用程序，我们将使用 8051 微控制器的仿真器。有几种可用；但是，我们将使用 MCU8051IDE，因为它在 Ubuntu 存储库中已经准备好了。

我们将其安装为常规的 Ubuntu 软件包，如下所示：

```cpp
# apt install -y mcu8051ide
```

这是一个 GUI IDE，需要 X Window 系统才能运行。如果您使用 Linux 或 Windows 作为工作环境，请考虑直接从[`sourceforge.net/projects/mcu8051ide/files/`](https://sourceforge.net/projects/mcu8051ide/files/)安装和运行它。

我们创建的简单程序定义了一个名为`Counter`的全局变量，如下所示*：*

```cpp
volatile int Counter = 0;
```

这被定义为`volatile`，表示它可以在外部更改，并且编译器不应尝试优化代码以消除它。

接下来，我们定义了一个名为`timer0_ISR`的简单函数*：*

```cpp
void timer0_ISR (void) __interrupt(1)
```

它不接受任何参数，也不返回任何值。它唯一的作用是增加`Counter`变量。它声明了一个重要的属性，称为`__interrupt(1)`，以让编译器知道它是一个中断处理程序，并且它服务于中断号 1。编译器会自动生成代码，自动更新中断向量数组的相应条目。

在定义 ISR 本身之后，我们配置定时器的参数：

```cpp
TMOD = 0x03; 
TH0 = 0x0; 
TL0 = 0x0;
```

然后，我们打开定时器 0，如下所示：

```cpp
TR0 = 1;
```

以下命令启用定时器 0 的中断：

```cpp
ET0 = 1; 
```

以下代码启用所有中断：

```cpp
EA = 1;
```

在这一点上，我们的 ISR 被定时器的中断周期性地激活。我们运行一个无限循环，因为所有的工作都是在 ISR 内完成的：

```cpp
while (1); // do nothing 
```

当我们在模拟器中运行上述代码时，我们会看到`counter`变量的实际值随时间变化，表明我们的 ISR 被定时器激活。

# 使用 8 位自动重装模式生成 5 kHz 方波信号

在前面的示例中，我们学习了如何创建一个简单的 ISR，只进行计数器增量。让我们让中断例程做一些更有用的事情。在这个示例中，我们将学习如何编程 8051 微控制器，以便它生成具有给定频率的信号。

8051 微控制器有两个定时器 - 定时器 0 和定时器 1 - 都使用两个特殊功能寄存器：**定时器模式**（**TMOD**）和**定时器控制**（**TCON**）进行配置。定时器的值存储在 TH0 和 TL0 定时器寄存器中，用于定时器 0，以及 TH1 和 TL1 定时器寄存器用于定时器 1。

TMOD 和 TCON 位具有特殊含义。TMOD 寄存器的位定义如下：

| **位** | **定时器** | **名称** | **目的** |
| --- | --- | --- | --- |
| 0 | 0 | M0 | 定时器模式选择器 - 低位。 |
| 1 | 0 | M1 | 定时器模式选择器 - 高位。 |
| 2 | 0 | CT | 计数器（1）或定时器（0）模式。 |
| 3 | 0 | GATE | 使能定时器 1，但仅当 INT0 的外部中断为高时。 |
| 4 | 1 | M0 | 定时器模式选择器 - 低位。 |
| 5 | 1 | M1 | 定时器模式选择器 - 高位。 |
| 6 | 1 | CT | 计数器（1）或定时器（0）模式。 |
| 7 | 1 | GATE | 使能定时器 1，但仅当 INT1 的外部中断为高时。 |

低 4 位分配给定时器 0，而高 4 位分配给定时器 1。

M0 和 M1 位允许我们以四种模式之一配置定时器：

| **模式** | **M0** | **M1** | **描述** |
| --- | --- | --- | --- |
| 0 | 0 | 0 | 13 位模式。TL0 或 TL1 寄存器包含对应定时器值的低 5 位，TH0 或 TH1 寄存器包含对应定时器值的高 8 位。 |
| 1 | 0 | 1 | 16 位模式。TL0 或 TL1 寄存器包含对应定时器值的低 8 位，TH0 或 TH1 寄存器包含对应定时器值的高 8 位。 |
| 2 | 1 | 0 | 8 位模式自动重装。TL0 或 TL1 包含对应的定时器值，而 TH0 或 TL1 包含重装值。 |
| 3 | 1 | 1 | 定时器 0 的特殊 8 位模式 |

**定时器控制**（**TCON**）寄存器控制定时器中断。其位定义如下：

| **位** | **名称** | **目的** |
| --- | --- | --- |
| 0 | IT0 | 外部中断 0 控制位。 |
| 1 | IE0 | 外部中断 0 边沿标志。当 INT0 接收到高至低边沿信号时设置为 1。 |
| 2 | IT1 | 外部中断 1 控制位。 |
| 3 | IE1 | 外部中断 1 边沿标志。当 INT1 接收到高至低边沿信号时设置为 1。 |
| 4 | TR0 | 定时器 0 的运行控制。设置为 1 以启动，设置为 0 以停止定时器。 |
| 5 | TF0 | 定时器 0 溢出。当定时器达到其最大值时设置为 1。 |
| 6 | TR1 | 定时器 1 的运行控制。设置为 1 以启动，设置为 0 以停止定时器。 |
| 7 | TF1 | 定时器 1 溢出。当定时器达到其最大值时设置为 1。 |

我们将使用称为自动重载的 8051 定时器的特定模式。在这种模式下，TL0（定时器 1 的 TL1）寄存器包含计时器值，而 TH0（定时器 1 的 TH1）包含重载值。一旦 TL0 达到 255 的最大值，它就会生成溢出中断，并自动重置为重载值。

# 如何做...

按照以下步骤完成此操作：

1.  启动*mce8051ide*并创建一个名为`Test`的新项目。

1.  创建一个名为`generator.c`的新文件，并将以下代码片段放入其中。这将在 MCU 的`P0_0`引脚上生成 5 kHz 信号：

```cpp
#include<8051.h> 

void timer0_ISR (void) __interrupt(1) 
{ 
  P0_0 = !P0_0;
} 

void main(void) 
{ 
  TMOD = 0x02;
  TH0 = 0xa3; 
  TL0 = 0x0; 
  TR0 = 1;
  EA = 1; 
  while (1); // do nothing 
}
```

1.  选择工具|编译以构建代码。

1.  选择模拟器|启动/关闭菜单项以激活模拟器。

1.  选择模拟器|动画以以慢速模式运行程序。

# 它是如何工作的...

以下代码定义了定时器 0 的 ISR：

```cpp
void timer0_ISR (void) __interrupt(1) 
```

在每次定时器中断时，我们翻转 P0 的输入输出寄存器的 0 位。这将有效地在 P0 输出引脚上生成方波信号。

现在，我们需要弄清楚如何编程定时器以生成给定频率的中断。要生成 5 kHz 信号，我们需要以 10 kHz 频率翻转位，因为每个波包括一个高相位和一个低相位。

8051 MCU 使用外部振荡器作为时钟源。定时器单元将外部频率除以 12。对于常用作 8051 时间源的 11.0592 MHz 振荡器，定时器每 1/11059200*12 = 1.085 毫秒激活一次。

我们的定时器 ISR 应以 10 kHz 频率激活，或者每 100 毫秒激活一次，或者在每 100/1.085 = 92 个定时器滴答后激活一次。

我们将定时器 0 编程为以第二种模式运行，如下所示：

```cpp
TMOD = 0x02;
```

在这种模式下，我们将定时器的复位值存储在 TH0 寄存器中。ISR 由定时器溢出激活，这发生在定时器计数器达到最大值之后。第二种模式是 8 位模式，意味着最大值是 255。要使 ISR 每 92 个时钟周期激活一次，自动重载值应为 255-92 = 163，或者用十六进制表示为`0xa3`。

我们将自动重载值与初始定时器值一起存储在定时器寄存器中：

```cpp
TH0 = 0xa3; 
TL0 = 0x0;
```

定时器 0 被激活，如下所示：

```cpp
TR0 = 1;
```

然后，我们启用定时器中断：

```cpp
TR0 = 1;
```

最后，所有中断都被激活：

```cpp
EA = 1; 
```

从现在开始，我们的 ISR 每 100 微秒被调用一次，如下面的代码所示：

```cpp
P0_0 = !P0_0;
```

这会翻转`P0`寄存器的`0`位，从而在相应的输出引脚上产生 5 kHz 方波信号。

# 使用定时器 1 作为事件计数器来计算 1 Hz 脉冲

8051 定时器具有双重功能。当它们被时钟振荡器激活时，它们充当定时器。然而，它们也可以被外部引脚上的信号脉冲激活，即 P3.4（定时器 0）和 P3.5（定时器 1），充当计数器。

在这个示例中，我们将学习如何编程定时器 1，以便它计算 8051 处理器的 P3.5 引脚的激活次数。

# 如何做...

按照以下步骤完成此操作：

1.  打开 mcu8051ide。

1.  创建一个名为`Counters`的新项目。

1.  创建一个名为`generator.c`的新文件，并将以下代码片段放入其中。这将在每次定时器中断触发时递增一个计数器变量：

```cpp
#include<8051.h> 

volatile int counter = 0;
void timer1_ISR (void) __interrupt(3) 
{ 
  counter++;
} 

void main(void) 
{ 
  TMOD = 0x60;
  TH1 = 254; 
  TL1 = 254; 
  TR1 = 1;
  ET1 = 1;
  EA = 1; 
  while (1); // do nothing 
}
```

1.  选择工具|编译以构建代码。

1.  打开 Virtual HW 菜单，并选择 Simple Key...条目。将打开一个新窗口。

1.  在 Simple Keypad 窗口中，将端口 3 和位 5 分配给第一个键。然后，单击 ON 或 OFF 按钮以激活它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/5c45f07b-20cb-4009-93d0-312fa4abe748.png)

1.  选择模拟器|启动/关闭菜单项以激活模拟器。

1.  选择模拟器|动画以以动画模式运行程序，该模式在调试器窗口中显示对特殊寄存器的所有更改。

1.  切换到简单键盘窗口并单击第一个键。

# 工作原理...

在这个过程中，我们利用 8051 定时器的能力，使其作为计数器。我们以与普通定时器完全相同的方式定义中断服务例程。由于我们将定时器 1 用作计数器，我们使用中断线号`3`，如下所示：

```cpp
void timer1_ISR (void) __interrupt(3) 
```

中断例程的主体很简单。我们只递增`counter`变量。

现在，让我们确保 ISR 是由外部源而不是时钟振荡器激活的。为此，我们通过将`TMOD`特殊功能寄存器的 C/T 位设置为 1 来配置定时器 1：

```cpp
TMOD = 0x60;
```

同样的行配置定时器 1 以在 Mode 2 下运行- 8 位模式与自动重载。由于我们的目标是使中断例程在每次外部引脚激活时被调用，我们将自动重载和初始值设置为最大值`254`：

```cpp
TH1 = 254; 
TL1 = 254; 
```

接下来，我们启用定时器 1：

```cpp
 TR1 = 1;
```

然后，激活所有来自定时器 1 的中断，如下所示：

```cpp
 ET1 = 1;
 EA = 1;
```

之后，我们可以进入一个什么也不做的无限循环，因为所有的工作都是在中断服务例程中完成的：

```cpp
 while (1); // do nothing 
```

在这一点上，我们可以在模拟器中运行代码。但是，我们需要配置外部事件的来源。为此，我们利用 MCU8051IDE 支持的虚拟外部硬件组件之一-虚拟键盘。

我们配置其中一个键来激活 8051 的引脚 P3.5。当它在计数模式下使用时，该引脚被用作定时器 1 的源。

现在，我们运行代码。按下虚拟键会激活计数器。一旦计时器值溢出，我们的 ISR 就会被触发，递增`counter`变量。

# 还有更多...

在这个过程中，我们使用定时器 1 作为计数器。同样的方法也可以应用于计数器 0。在这种情况下，引脚 P3.4 应该被用作外部源。

# 串行接收和发送数据

8051 微控制器配备了内置的**通用异步收发器**（**UART**）端口，用于串行数据交换。

串行端口由名为**串行控制**（**SCON**）的**特殊功能寄存器**（**SFR**）控制。其位定义如下：

| **位** | **名称** | **目的** |
| --- | --- | --- |
| 0 | **RI**（**接收** **中断**的缩写） | 当一个字节完全接收时由 UART 设置 |
| 1 | **TI**（**传输** **中断**的缩写） | 当一个字节完全传输时由 UART 设置 |
| 2 | **RB8**（**接收** **位** **8**的缩写） | 在 9 位模式下存储接收数据的第九位。 |
| 3 | **TB8**（**传输位 8**的缩写） | 在 9 位模式下存储要传输的数据的第九位（见下文） |
| 4 | **REN**（**接收使能**的缩写） | 启用（1）或禁用（0）接收操作 |
| 5 | **SM2**（启用多处理器） | 为 9 位模式启用（1）或禁用（0）多处理器通信 |
| 6 | **SM1**（串行模式，高位） | 定义串行通信模式 |
| 7 | **SM0**（串行模式，低位） | 定义串行通信模式 |

8051 UART 支持四种串行通信模式，所有这些模式都由 SM1 和 SM0 位定义：

| **模式** | **SM0** | **SM1** | **描述** |
| --- | --- | --- | --- |
| 0 | 0 | 0 | 移位寄存器，固定波特率 |
| 1 | 0 | 1 | 8 位 UART，波特率由定时器 1 设置 |
| 2 | 1 | 0 | 9 位 UART，固定波特率 |
| 3 | 1 | 1 | 9 位 UART，波特率由定时器 1 设置 |

在这个过程中，我们将学习如何使用中断来实现使用可编程波特率的 8 位 UART 模式进行简单数据交换。

# 如何做...

按照以下步骤完成此过程：

1.  打开 mcu8051ide 并创建一个新项目。

1.  创建一个名为`serial.c`的新文件，并将以下代码片段复制到其中。这段代码将接收到的字节复制到`P0`输出寄存器中。这与 MCU 上的通用输入/输出引脚相关联：

```cpp
#include<8051.h>

void serial_isr() __interrupt(4) { 
    if(RI == 1) {
        P0 = SBUF;
        RI = 0;
    }
 }

void main() {
    SCON = 0x50;
    TMOD = 0x20;
    TH1 = 0xFD;
    TR1 = 1; 
    ES = 1;
    EA = 1;

    while(1);
 }
```

1.  选择工具 | 编译以构建代码。

1.  选择模拟器 | 启动/关闭菜单项以激活模拟器。

# 工作原理...

我们为中断线`4`定义了一个 ISR，用于串行端口事件触发：

```cpp
void serial_isr() __interrupt(4)
```

一旦接收到一个完整的字节并存储在**串行缓冲寄存器**（**SBUF**）中，中断例程就会被调用。我们的中断服务程序的实现只是将接收到的字节复制到输入/输出端口，即`P0`：

```cpp
P0 = SBUF;
```

然后，它重置 RI 标志以启用即将到来的字节的中断。

为了使中断按预期工作，我们需要配置串行端口和定时器。首先，配置串行端口如下：

```cpp
SCON = 0x50;
```

根据上表，这意味着**串行控制寄存器**（**SCON**）的 SM1 和 REN 位仅设置为 1，从而选择通信模式 1。这是一个由定时器 1 定义波特率的 8 位 UARS。然后，它启用接收器。

由于波特率由定时器 1 定义，下一步是配置定时器，如下所示：

```cpp
TMOD = 0x20;
```

上述代码配置定时器 1 使用模式 2，即 8 位自动重载模式。

将 0xFD 加载到 TH1 寄存器中，将波特率设置为 9600 bps。然后，我们启用定时器 1、串行中断和所有中断。

# 还有更多...

数据传输可以以类似的方式实现。如果您向 SBUF 特殊寄存器写入数据，8051 UART 将开始传输。完成后，将调用串行中断并将 TI 标志设置为 1。


# 第五章：调试、日志记录和性能分析

调试和性能分析是任何类型应用程序开发工作流程中的重要部分。在嵌入式环境中，这些任务需要开发人员特别注意。嵌入式应用程序在可能与开发人员工作站非常不同的系统上运行，并且通常具有有限的资源和用户界面功能。

开发人员应该提前计划如何在开发阶段调试他们的应用程序，以及如何确定生产环境中问题的根本原因，并加以修复。

通常，解决方案是使用目标设备的仿真器以及嵌入式系统供应商提供的交互式调试器。然而，对于更复杂的系统，完整和准确的仿真几乎是不可行的，远程调试是最可行的解决方案。

在许多情况下，使用交互式调试器是不可能或根本不切实际的。程序在断点停止后几毫秒内硬件状态可能会发生变化，开发人员没有足够的时间来分析它。在这种情况下，开发人员必须使用广泛的日志记录进行根本原因分析。

在本章中，我们将重点介绍基于**SoC**（**片上系统**）和运行 Linux 操作系统的更强大系统的调试方法。我们将涵盖以下主题：

+   在**GDB**（GNU 项目调试器的缩写）中运行您的应用程序

+   使用断点

+   处理核心转储

+   使用 gdbserver 进行调试

+   添加调试日志

+   使用调试和发布版本

这些基本的调试技术将在本书中以及在您处理任何类型嵌入式应用程序的工作中有很大帮助。

# 技术要求

在本章中，我们将学习如何在**ARM**（**Acorn RISC Machines**的缩写）平台仿真器中调试嵌入式应用程序。此时，您应该已经在笔记本电脑或台式电脑上运行的虚拟化 Linux 环境中配置了两个系统：

+   Ubuntu Linux 作为构建系统在 Docker 容器中

+   Debian Linux 作为目标系统在**QEMU**（**快速仿真器**）ARM 仿真器中

要了解交叉编译的理论并设置开发环境，请参考第二章中的示例，*设置环境*。

# 在 GDB 中运行您的应用程序

在这个示例中，我们将学习如何在目标系统上使用调试器运行一个示例应用程序，以及尝试一些基本的调试技术。

GDB 是一个开源且广泛使用的交互式调试器。与大多数作为**集成开发环境**（**IDE**）产品的一部分提供的调试器不同，GDB 是一个独立的命令行调试器。这意味着它不依赖于任何特定的 IDE。正如您在示例中所看到的，您可以使用纯文本编辑器来处理应用程序的代码，同时仍然能够进行交互式调试，使用断点，查看变量和堆栈跟踪的内容，以及更多。

GDB 的用户界面是极简的。您可以像在 Linux 控制台上工作一样运行它——通过输入命令并分析它们的输出。这种简单性使其非常适合嵌入式项目。它可以在没有图形子系统的系统上运行。如果目标系统只能通过串行连接或 ssh shell 访问，它尤其方便。由于它没有花哨的用户界面，它可以在资源有限的系统上运行。

在这个示例中，我们将使用一个人工样本应用程序，它会因异常而崩溃。它不会记录任何有用的信息，异常消息太模糊，无法确定崩溃的根本原因。我们将使用 GDB 来确定问题的根本原因。

# 如何做...

我们现在将创建一个在特定条件下崩溃的简单应用程序：

1.  在您的工作目录`~/test`中，创建一个名为`loop`的子目录。

1.  使用您喜欢的文本编辑器在`loop`子目录中创建一个名为`loop.cpp`的文件。

1.  让我们将一些代码放入`loop.cpp`文件中。我们从包含开始：

```cpp
#include <iostream>
#include <chrono>
#include <thread>
#include <functional>
```

1.  现在，我们定义程序将包含的三个函数。第一个是`runner`：

```cpp
void runner(std::chrono::milliseconds limit,
            std::function<void(int)> fn,
            int value) {
  auto start = std::chrono::system_clock::now();
  fn(value);
  auto end = std::chrono::system_clock::now();
  std::chrono::milliseconds delta =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  if (delta > limit) {
    throw std::runtime_error("Time limit exceeded");
  }
  }
```

1.  第二个函数是`delay_ms`：

```cpp
void delay_ms(int count) {
  for (int i = 0; i < count; i++) {
    std::this_thread::sleep_for(std::chrono::microseconds(1050));
  }
  }
```

1.  最后，我们添加入口函数`main`：

```cpp
int main() {
  int max_delay = 10;
  for (int i = 0; i < max_delay; i++) {
    runner(std::chrono::milliseconds(max_delay), delay_ms, i);
  }
  return 0;
  }
```

1.  在`loop`子目录中创建一个名为`CMakeLists.txt`的文件，并包含以下内容：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(loop)
add_executable(loop loop.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "-g --std=c++11")

set(CMAKE_C_COMPILER /usr/bin/arm-linux-gnueabi-gcc)
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
```

1.  现在，切换到构建系统终端，并通过运行以下命令将当前目录更改为`/mnt/loop`。

```cpp
$ cd /mnt/loop
```

1.  按照以下方式构建应用程序：

```cpp
$ cmake . && make
```

1.  切换回您的本机环境，在`loop`子目录中找到`loop`输出文件，并通过 ssh 将其复制到目标系统。使用用户帐户。切换到目标系统终端。根据需要使用用户凭据登录。现在，使用`gdb`运行`loop`可执行二进制文件：

```cpp
$ gdb ./loop
```

1.  调试器已启动，并显示命令行提示（`gdb`）。要运行应用程序，请键入`run`命令：

```cpp
(gdb) run
```

1.  您可以看到应用程序由于运行时异常而异常终止。异常消息`Time limit exceeded`给了我们一个线索，但并没有指出发生异常的具体条件。让我们试着确定这一点。首先，让我们检查崩溃应用程序的堆栈跟踪：

```cpp
(gdb) bt
```

1.  这显示了从顶级函数`main`到库函数`__GI_abort`的七个堆栈帧，后者实际上终止了应用程序。正如我们所看到的，只有帧`7`和`6`属于我们的应用程序，因为只有它们在`loop.cpp`中定义。让我们仔细看一下`frame 6`，因为这是抛出异常的函数：

```cpp
(gdb) frame 6
```

1.  运行`list`命令来查看附近的代码：

```cpp
(gdb) list
```

1.  正如我们所看到的，如果 delta 变量的值超过 limit 变量的值，就会抛出异常。但是这些值是什么？运行`info locals`命令来找出这一点：

```cpp
(gdb) info locals
```

1.  我们无法在这里看到限制变量的值。使用`info args`命令来查看它：

```cpp
(gdb) info args
```

1.  现在，我们可以看到限制是`10`，而 delta 是`11`。当使用`fn`参数设置为`delay_ms`函数，并且`value`参数的值设置为`7`时，崩溃发生。

# 它是如何工作的...

该应用程序是故意创建的，在某些条件下会崩溃，并且没有提供足够的信息来确定这些条件。该应用程序由两个主要函数组成——`runner`和`delay_ms`。

`runner`函数接受三个参数——时间限制、一个参数的函数和函数参数值。它运行作为参数提供的函数，传递值，并测量经过的时间。如果时间超过时间限制，它会抛出异常。

`delay_ms`函数执行延迟。但是，它的实现是错误的，它将每毫秒视为由 1100 微秒而不是 1000 微秒组成。

`main`函数在`loop`目录中运行 runner，提供 10 毫秒作为时间限制的修复值和`delay_ms`作为要运行的函数，但增加`value`参数的值。在某个时候，`delay_ms`函数超过了时间限制，应用程序崩溃了。

首先，我们为 ARM 平台构建应用程序，并将其传输到模拟器上运行：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/52c9bbb6-e17c-4961-a4da-0e45d3a73859.png)

重要的是要向编译器传递`-g`参数。此参数指示编译器向生成的二进制文件添加调试符号。我们将其添加到`CMakeLists.txt`文件中的`CMAKE_CXX_FLAGS`参数中，如下所示：

```cpp
SET(CMAKE_CXX_FLAGS "-g --std=c++11")
```

现在，我们运行调试器，并将应用程序可执行文件名作为其参数：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/e3b7393c-2d4c-4b8d-a1dd-1f5ea2c2ced8.png)

应用程序不会立即运行。我们使用`run` GDB 命令启动它，并观察它在短时间内崩溃：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/66aacaec-d965-40bc-bac7-e0de3e630951.png)

接下来，我们使用`backtrace`命令来查看堆栈跟踪：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/b394f587-a045-48f3-8c60-299f1cbb9fc7.png)

对堆栈跟踪的分析显示`frame 6`应该给我们更多信息来揭示根本原因。通过接下来的步骤，我们切换到`frame 6`并审查相关的代码片段：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/ee18e675-c717-4500-8d75-c88fd036ad38.png)

接下来，我们分析本地变量和函数参数的值，以确定它们与时间限制的关系：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/a37ff8ac-9ac1-4185-9e4c-d641e7c05ff4.png)

我们确定当传递给`delay_ms`的值达到`7`时发生崩溃，而不是预期的`11`，这在正确实现延迟的情况下是预期的。

# 还有更多...

GDB 命令通常接受多个参数来微调它们的行为。使用`help`命令来了解每个命令的更多信息。例如，这是`help bt`命令的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/96d294ad-4432-4294-bd38-b8480c1ccec6.png)

这显示了用于审查和分析堆栈跟踪的`bt`命令的信息。类似地，您可以获取关于 GDB 支持的所有其他命令的信息。

# 使用断点

在这个教程中，我们将学习在使用 GDB 时更高级的调试技术。我们将使用相同的示例应用程序，并使用断点来找到实际延迟与`delay_ms`参数值的依赖关系。

在 GDB 中使用断点与在集成 IDE 中使用断点类似，唯一的区别是开发人员不是使用内置编辑器来导航源代码，而是要学会显式使用行号、文件名或函数名。

这比点击运行调试器不太方便，但是灵活性使开发人员能够创建强大的调试场景。在这个教程中，我们将学习如何在 GDB 中使用断点。

# 如何做到...

在这个教程中，我们将使用与第一个教程相同的环境和相同的测试应用程序。参考第 1 到 9 步的*在 GDB 中运行您的应用程序*教程来构建应用程序并将其复制到目标系统上：

1.  我们想要调试我们的`runner`函数。让我们看一下它的内容。在 gdb shell 中，运行以下程序：

```cpp
(gdb) list runner,delay_ms
```

1.  我们想要看到每次迭代中`delta`的变化。让我们在该行设置一个断点：

```cpp
14 if (delta > limit) {
```

1.  使用`break 14`命令在第 14 行设置一个断点：

```cpp
(gdb) break 14
```

1.  现在运行程序：

```cpp
(gdb) run
```

1.  检查`delta`的值：

```cpp
(gdb) print delta 
$1 = {__r = 0}
```

1.  继续执行程序，输入`continue`或者`c`：

```cpp
(gdb) c
```

1.  再次检查`delta`的值：

```cpp
(gdb) print delta
```

1.  正如我们预期的那样，`delta`的值在每次迭代中都会增加，因为`delay_ms`需要越来越多的时间。

1.  每次运行`print delta`都不方便。让我们使用名为`command`的命令来自动化它：

```cpp
(gdb) command
```

1.  再次运行`c`。现在，每次停止后都会显示`delta`的值：

```cpp
(gdb) c
```

1.  然而，输出太冗长了。让我们通过再次输入`command`并编写以下指令来使 GDB 输出静音。现在，运行`c`或`continue`命令几次以查看差异：

```cpp
(gdb) command
Type commands for breakpoint(s) 1, one per line.
End with a line saying just "end".
>silent
>print delta
>end
(gdb) c
```

1.  我们可以使用`printf`命令使输出更加简洁，如下所示：

```cpp
(gdb) command
Type commands for breakpoint(s) 1, one per line.
End with a line saying just "end".
>silent
>printf "delta=%d, expected=%d\n", delta.__r, value
>end
(gdb) c
```

现在，我们可以看到两个值，计算出的延迟和预期的延迟，并且可以看到它们随时间的变化而发散。

# 它是如何工作的...

在这个教程中，我们想要设置一个断点来调试`runner`函数。由于 GDB 没有内置编辑器，我们需要知道设置断点的行号。虽然我们可以直接从文本编辑器中获取它，但另一种方法是在 GDB 中查看相关代码片段。我们使用带有两个参数的`gdb`命令列表 - 函数名称，以显示`runner`函数的第一行和`delay_ms`函数的第一行之间的代码行。这有效地显示了函数`runner`的内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/482a8b75-c389-4e61-b14d-de3f5cd496b9.png)

在*步骤 4*，使用`break 14`命令在第 14 行设置断点，并运行程序。执行将在断点处停止：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/c22a841e-1537-4806-b134-47c6733547bc.png)

我们使用`print`命令检查`delta`变量的值，并使用`continue`命令继续执行程序，由于在循环中调用了`runner`函数，它再次停在相同的断点处：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/3e1b1f31-812a-4201-8a63-1866a3febe7a.png)

接下来，我们尝试更高级的技术。我们定义一组 GDB 命令，以在触发断点时执行。我们从一个简单的`print`命令开始。现在，每次我们继续执行，我们都可以看到`delta`变量的值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/55443211-11e7-43c4-a6c2-6a135a946c64.png)

接下来，我们使用`silent`命令禁用辅助 GDB 输出，以使输出更加简洁：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/7175eb69-bc52-4946-b777-6277cae952a9.png)

最后，我们使用`printf`命令格式化具有两个最有趣变量的消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/7b3fe1fb-b927-4590-9e68-2172dde5d955.png)

正如你所看到的，GDB 为开发人员提供了很多灵活性，使得即使缺乏图形界面，调试也变得更加舒适。

# 还有更多...

重要的是要记住，优化选项`-O2`和`-O3`可能导致编译器完全消除一些代码行。如果将断点设置为这些行，这些断点将永远不会触发。为避免这种情况，关闭调试构建的编译器优化。

# 处理核心转储

在第一个教程中，我们学习了如何使用交互式命令行调试器确定崩溃应用程序的根本原因。但是，在生产环境中，应用程序崩溃时，有时无法或不切实际地在测试系统上重现相同的问题，从 GDB 中运行应用程序。 

Linux 提供了一种机制，可帮助分析崩溃的应用程序，即使它们不是直接从 GDB 中运行的。当应用程序异常终止时，操作系统将其内存映像保存到名为`core`的文件中。在本教程中，我们将学习如何配置 Linux 以生成崩溃应用程序的核心转储，以及如何使用 GDB 进行分析。

# 如何做...

我们将确定一个应用程序崩溃的根本原因，该应用程序未在 GDB 中运行：

1.  在本教程中，我们将使用与第一个教程中相同的环境和相同的测试应用程序。请参阅第一个教程的*步骤 1*至*7*，构建应用程序并将其复制到目标系统。

1.  首先，我们需要启用生成崩溃应用程序的核心转储。在大多数 Linux 发行版中，默认情况下关闭此功能。运行`ulimit -c`命令检查当前状态：

```cpp
$ ulimit -c
```

1.  前一个命令报告的值是要生成的核心转储的最大大小。零表示没有核心转储。要增加限制，我们需要首先获得超级用户权限。运行`su -`命令。提示输入`Password`时，输入`root`：

```cpp
$ su -
Password:
```

1.  运行`ulimit -c unlimited`命令允许任意大小的核心转储：

```cpp
# ulimit -c unlimited
```

1.  现在，通过按*Ctrl* + *D*或运行`logout`命令退出 root shell。

1.  前面的命令仅为超级用户更改了核心转储限制。要将其应用于当前用户，请在用户 shell 中再次运行相同的命令：

```cpp
$ ulimit -c unlimited
```

1.  确保限制已更改：

```cpp
$ ulimit -c
unlimited
```

1.  现在，像往常一样运行应用程序：

```cpp
$ ./loop 
```

1.  它将以异常崩溃。运行`ls`命令检查当前目录中是否创建了核心文件：

```cpp
$ ls -l core
-rw------- 1 dev dev 536576 May 31 00:54 core
```

1.  现在，运行`gdb`，传递可执行文件和`core`文件作为参数：

```cpp
$ gdb ./loop core
```

1.  在 GDB shell 中，运行`bt`命令查看堆栈跟踪：

```cpp
(gdb) bt
```

1.  您可以看到与从`gdb`内部运行的应用程序相同的堆栈跟踪。但是，在这种情况下，我们看到了核心转储的堆栈跟踪。

1.  在这一点上，我们可以使用与第一个教程中相同的调试技术来缩小崩溃原因。

# 它是如何工作的...

核心转储功能是 Linux 和其他类 Unix 操作系统的标准功能。然而，在每种情况下都创建核心文件并不实际。由于核心文件是进程内存的快照，它们可能在文件系统上占用几兆甚至几十几个 G 的空间。在许多情况下，这是不可接受的。

开发人员需要明确指定操作系统允许生成的核心文件的最大大小。这个限制，以及其他限制，可以使用`ulimit`命令来设置。

我们运行`ulimit`两次，首先为超级用户 root 移除限制，然后为普通用户/开发人员移除限制。需要两阶段的过程，因为普通用户的限制不能超过超级用户的限制。

在我们移除了核心文件大小的限制后，我们在没有 GDB 的情况下运行我们的测试应用程序。预期地，它崩溃了。崩溃后，我们可以看到当前目录中创建了一个名为`core`的新文件。

当我们运行我们的应用程序时，它崩溃了。通常情况下，我们无法追踪崩溃的根本原因。然而，由于我们启用了核心转储，操作系统自动为我们创建了一个名为`core`的文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/a897ffd1-0aa8-4f4d-b1d3-a9e2941e9e77.png)

核心文件是所有进程内存的二进制转储，但没有额外的工具很难分析它。幸运的是，GDB 提供了必要的支持。

我们运行 GDB 传递两个参数——可执行文件的路径和核心文件的路径。在这种模式下，我们不从 GDB 内部运行应用程序。我们已经在核心转储中冻结了应用程序在崩溃时的状态。GDB 使用可执行文件将`core`文件中的内存地址绑定到函数和变量名：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/8f81cb30-8138-4cd4-8688-2db1c3152d52.png)

因此，即使应用程序未从调试器中运行，您也可以在交互式调试器中分析崩溃的应用程序。当我们调用`bt`命令时，GDB 会显示崩溃时的堆栈跟踪：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/56155e9f-ad93-4de6-b78e-4511160d4840.png)

这样，即使最初没有在调试器中运行，我们也可以找出应用程序崩溃的根本原因。

# 还有更多...

使用 GDB 分析核心转储是嵌入式应用程序的广泛使用和有效实践。然而，要使用 GDB 的全部功能，应用程序应该构建时支持调试符号。

然而，在大多数情况下，嵌入式应用程序会在没有调试符号的情况下部署和运行，以减小二进制文件的大小。在这种情况下，对核心转储的分析变得更加困难，可能需要一些特定架构的汇编语言和数据结构实现的内部知识。

# 使用 gdbserver 进行调试

嵌入式开发的环境通常涉及两个系统——构建系统和目标系统，或者模拟器。尽管 GDB 的命令行界面使其成为低性能嵌入式系统的不错选择，但在许多情况下，由于远程通信的高延迟，目标系统上的交互式调试是不切实际的。

在这种情况下，开发人员可以使用 GDB 提供的远程调试支持。在这种设置中，嵌入式应用程序使用 gdbserver 在目标系统上启动。开发人员在构建系统上运行 GDB，并通过网络连接到 gdbserver。

在这个配方中，我们将学习如何使用 GDB 和 gdbserver 开始调试应用程序。

# 准备就绪...

按照第二章的*连接到嵌入式系统*配方，*设置环境*，在目标系统上有`hello`应用程序可用。

# 如何做...

我们将使用前面的示例中使用的相同应用程序，但现在我们将在不同的环境中运行 GDB 和应用程序：

1.  切换到目标系统窗口，然后输入*Ctrl* + *D*以注销当前用户会话。

1.  以`user`身份登录，使用`user`密码。

1.  在`gdbserver`下运行`hello`应用程序：

```cpp
$ gdbserver 0.0.0.0:9090 ./hello
```

1.  切换到构建系统终端，并将目录更改为`/mnt`：

```cpp
# cd /mnt
```

1.  运行`gdb`，将应用程序二进制文件作为参数传递：

```cpp
# gdb -q hello
```

1.  通过在 GDB 命令行中输入以下命令来配置远程连接：

```cpp
target remote X.X.X.X:9090
```

1.  最后，键入`continue`命令：

```cpp
 continue
```

现在程序正在运行，我们可以看到它的输出并像在本地运行一样对其进行调试。

# 工作原理...

首先，我们以 root 用户身份登录到目标系统并安装 gdbserver，除非它已经安装。安装完成后，我们再次使用用户凭据登录并运行 gdbserver，将要调试的应用程序的名称、IP 地址和要监听的端口作为其参数传递。

然后，我们切换到我们的构建系统并在那里运行 GDB。但是，我们不直接在 GDB 中运行应用程序，而是指示 GDB 使用提供的 IP 地址和端口建立与远程主机的连接。之后，您在 GDB 提示符处键入的所有命令都将传输到 gdbserver 并在那里执行。

# 添加调试日志

日志记录和诊断是任何嵌入式项目的重要方面。在许多情况下，使用交互式调试器是不可能或不切实际的。在程序停在断点后，硬件状态可能在几毫秒内发生变化，开发人员没有足够的时间来分析它。收集详细的日志数据并使用工具进行分析和可视化是高性能、多线程、时间敏感的嵌入式系统的更好方法。

日志记录本身会引入一定的延迟。首先，需要时间来格式化日志消息并将其放入日志流中。其次，日志流应可靠地存储在持久存储器中，例如闪存卡或磁盘驱动器，或者发送到远程系统。

在本教程中，我们将学习如何使用日志记录而不是交互式调试来查找问题的根本原因。我们将使用不同日志级别的系统来最小化日志记录引入的延迟。

# 如何做...

我们将修改我们的应用程序以输出对根本原因分析有用的信息：

1.  转到您的工作目录`~/test`，并复制`loop`项目目录。将副本命名为`loop2`。切换到`loop2`目录。

1.  使用文本编辑器打开`loop.cpp`文件。

1.  添加一个`include`：

```cpp
#include <iostream>
#include <chrono>
#include <thread>
#include <functional>

#include <syslog.h>
```

1.  通过在以下代码片段中突出显示的方式修改`runner`函数，添加对`syslog`函数的调用：

```cpp
void runner(std::chrono::milliseconds limit,
            std::function<void(int)> fn,
            int value) {
  auto start = std::chrono::system_clock::now();
  fn(value);
  auto end = std::chrono::system_clock::now();
  std::chrono::milliseconds delta =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
 syslog(LOG_DEBUG, "Delta is %ld",
         static_cast<long int>(delta.count()));
  if (delta > limit) {
 syslog(LOG_ERR, 
 "Execution time %ld ms exceeded %ld ms limit",
 static_cast<long int>(delta.count()),
 static_cast<long int>(limit.count()));
    throw std::runtime_error("Time limit exceeded");
  }
}
```

1.  同样，更新`main`函数以初始化和完成`syslog`：

```cpp
int main() {
 openlog("loop3", LOG_PERROR, LOG_USER);
  int max_delay = 10;
  for (int i = 0; i < max_delay; i++) {
    runner(std::chrono::milliseconds(max_delay), delay_ms, i);
  }
 closelog();
  return 0;
}
```

1.  切换到构建系统终端。转到`/mnt/loop2`目录并运行程序：

```cpp
# cmake && make
```

1.  将生成的`binary`文件复制到目标系统并运行它：

```cpp
$ ./loop 
```

调试输出冗长，并提供更多上下文以找到问题的根本原因。

# 工作原理...

在本教程中，我们使用标准日志记录工具`syslog`添加了日志记录。首先，我们通过调用`openlog`来初始化我们的日志记录：

```cpp
 openlog("loop3", LOG_PERROR, LOG_USER);
```

接下来，我们将日志记录添加到`runner`函数中。有不同的日志记录级别，可以方便地过滤日志消息，从最严重到最不严重。我们使用`LOG_DEBUG`级别记录`delta`值，该值表示`runner`调用的函数实际运行的时间有多长：

```cpp
 syslog(LOG_DEBUG, "Delta is %d", delta);
```

此级别用于记录对应用程序调试有用的详细信息，但在生产环境中运行应用程序时可能会过于冗长。

但是，如果`delta`超过限制，我们将使用`LOG_ERR`级别记录此情况，以指示通常不应发生此情况并且这是一个错误：

```cpp
 syslog(LOG_ERR, 
 "Execution time %ld ms exceeded %ld ms limit",
 static_cast<long int>(delta.count()),
 static_cast<long int>(limit.count()));
```

在从应用程序返回之前，我们关闭日志记录以确保所有日志消息都得到适当保存：

```cpp
 closelog();
```

当我们在目标系统上运行应用程序时，我们可以在屏幕上看到我们的日志消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/fee9835c-ae1e-48c7-ac4c-7d5061ab539c.png)

由于我们使用标准的 Linux 日志记录，我们也可以在系统日志中找到消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/2aafea69-e7e5-4925-a431-9efec515aca3.png)

如您所见，记录并不难实现，但在调试和正常操作期间，它对于找出应用程序中各种问题的根本原因非常有帮助。

# 还有更多...

有许多日志记录库和框架，可能比标准记录器更适合特定任务；例如，*Boost.Log*，网址为[`theboostcpplibraries.com/boost.log`](https://theboostcpplibraries.com/boost.log)，以及*spdlog*，网址为[`github.com/gabime/spdlog`](https://github.com/gabime/spdlog)。它们提供了比`syslog`的通用 C 接口更方便的 C++接口。在开始项目工作时，请检查现有的日志记录库，并选择最适合您要求的库。

# 使用调试和发布构建

正如我们在前面的食谱中所学到的，记录会带来相关成本。它会延迟格式化日志消息并将其写入持久存储或远程系统。

使用日志级别有助于通过跳过将一些消息写入日志文件来减少开销。但是，在将消息传递给`log`函数之前，消息通常会被格式化。例如，在系统错误的情况下，开发人员希望将系统报告的错误代码添加到日志消息中。尽管字符串格式化通常比将数据写入文件要便宜，但对于负载高的系统或资源有限的系统来说，这可能仍然是一个问题。

编译器添加的调试符号不会增加运行时开销。但是，它们会增加生成二进制文件的大小。此外，编译器进行的性能优化可能会使交互式调试变得困难。

在本食谱中，我们将学习如何通过分离调试和发布构建并使用 C 预处理器宏来避免运行时开销。

# 如何做...

我们将修改我们在前面的食谱中使用的应用程序的构建规则，以拥有两个构建目标——调试和发布：

1.  转到您的工作目录`~/test`，并复制`loop2`项目目录。将副本命名为`loop3`。切换到`loop3`目录。

1.  使用文本编辑器打开`CMakeLists.txt`文件。替换以下行：

```cpp
SET(CMAKE_CXX_FLAGS "-g --std=c++11")
```

1.  前面的行需要替换为以下行：

```cpp
SET(CMAKE_CXX_FLAGS_RELEASE "--std=c++11")
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_RELEASE} -g -DDEBUG")
```

1.  使用文本编辑器打开`loop.cpp`文件。通过添加突出显示的行来修改文件：

```cpp
#include <iostream>
#include <chrono>
#include <thread>
#include <functional>
#include <cstdarg>

#ifdef DEBUG
#define LOG_DEBUG(fmt, args...) fprintf(stderr, fmt, args)
#else
#define LOG_DEBUG(fmt, args...)
#endif

void runner(std::chrono::milliseconds limit,
            std::function<void(int)> fn,
            int value) {
  auto start = std::chrono::system_clock::now();
  fn(value);
  auto end = std::chrono::system_clock::now();
  std::chrono::milliseconds delta =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
 LOG_DEBUG("Delay: %ld ms, max: %ld ms\n",
            static_cast<long int>(delta.count()),
            static_cast<long int>(limit.count()));
  if (delta > limit) {
    throw std::runtime_error("Time limit exceeded");
  }
}
```

1.  切换到构建系统终端。转到`/mnt/loop3`目录并运行以下代码：

```cpp
# cmake -DCMAKE_BUILD_TYPE=Release . && make
```

1.  将生成的`loop`二进制文件复制到目标系统并运行它：

```cpp
$ ./loop 
```

1.  如您所见，该应用程序不会生成任何调试输出。现在让我们使用`ls -l`命令检查其大小：

```cpp
$ ls -l loop
-rwxr-xr-x 1 dev dev 24880 Jun 1 00:50 loop
```

1.  生成的二进制文件的大小为 24 KB。现在，让我们构建`Debug`构建并进行如下比较：

```cpp
$ cmake -DCMAKE_BUILD_TYPE=Debug && make clean && make
```

1.  检查可执行文件的大小：

```cpp
$ ls -l ./loop
-rwxr-xr-x 1 dev dev 80008 Jun 1 00:51 ./loop
```

1.  可执行文件的大小现在是 80 KB。它比发布构建大三倍以上。像以前一样运行它：

```cpp
$ ./loop 
```

如您所见，输出现在不同了。

# 它是如何工作的...

我们从用于*添加调试日志*食谱的项目副本开始，并创建两个不同的构建配置：

+   **调试**：具有交互式调试和调试日志支持的配置

+   **发布**：高度优化的配置，在编译时禁用了所有调试支持

为了实现它，我们利用了`CMake`提供的功能。它支持开箱即用的不同构建类型。我们只需要分别为发布和调试构建定义编译选项。

我们为发布构建定义的唯一构建标志是要使用的 C++标准。我们明确要求代码符合 C++11 标准：

```cpp
SET(CMAKE_CXX_FLAGS_RELEASE "--std=c++11")
```

对于调试构建，我们重用与发布构建相同的标志，将其引用为`${CMAKE_CXX_FLAGS_RELEASE}`，并添加两个选项。`-g`指示编译器向目标可执行二进制文件添加调试符号，而`-DDEBUG`定义了一个预处理宏`DEBUG`。

我们在`loop.cpp`的代码中使用`DEBUG`宏来选择`LOG_DEBUG`宏的两种不同实现。

如果定义了`DEBUG`，`LOG_DEBUG`会扩展为调用`fprintf`函数，该函数在标准错误通道中执行实际的日志记录。然而，如果未定义`DEBUG`，`LOG_DEBUG`会扩展为空字符串。这意味着在这种情况下，`LOG_DEBUG`不会产生任何代码，因此不会增加任何运行时开销。

我们在运行函数的主体中使用`LOG_DEBUG`来记录实际延迟和限制的值。请注意，`LOG_DEBUG`周围没有`if` - 格式化和记录数据或不执行任何操作的决定不是由我们的程序在运行时做出的，而是由代码预处理器在构建应用程序时做出的。

要选择构建类型，我们调用`cmake`，将构建类型的名称作为命令行参数传递：

```cpp
cmake -DCMAKE_BUILD_TYPE=Debug
```

`CMake`只生成一个`Make`文件来实际构建我们需要调用`make`的应用程序。我们可以将这两个命令合并成一个单独的命令行：

```cpp
cmake -DCMAKE_BUILD_TYPE=Release && make
```

第一次构建和运行应用程序时，我们选择发布版本。因此，我们看不到任何调试输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/55077ea0-cd5e-411c-82f1-286108dc17f0.png)

之后，我们使用调试构建类型重新构建我们的应用程序，并在运行时看到不同的结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/719acbab-871a-4922-88e4-07915e394e61.png)

通过调试和发布构建，您可以获得足够的信息进行舒适的调试，但请确保生产构建不会有任何不必要的开销。

# 还有更多...

在复杂项目中切换发布和调试构建时，请确保所有文件都已正确重建。最简单的方法是删除所有先前的构建文件。在使用`make`时，可以通过调用`make clean`命令来完成。

它可以作为命令行的一部分与`cmake`和`make`一起添加：

```cpp
cmake -DCMAKE_BUILD_TYPE=Debug && make clean && make
```

将所有三个命令合并成一行对开发人员更加方便。


# 第六章：内存管理

内存效率是嵌入式应用的主要要求之一。由于目标嵌入式平台通常具有有限的性能和内存能力，开发人员需要知道如何以最有效的方式使用可用内存。

令人惊讶的是，最有效的方式并不一定意味着使用最少的内存。由于嵌入式系统是专用的，开发人员预先知道将在系统上执行哪些应用程序或组件。在一个应用程序中节省内存并不会带来任何收益，除非同一系统中运行的另一个应用程序可以使用额外的内存。这就是嵌入式系统中内存管理最重要的特征是确定性或可预测性的原因。知道一个应用程序在任何负载下可以使用两兆字节的内存比知道一个应用程序大部分时间可以使用一兆字节的内存，但偶尔可能需要三兆字节更重要得多。

同样，可预测性也适用于内存分配和释放时间。在许多情况下，嵌入式应用更倾向于花费更多内存以实现确定性定时。

在本章中，我们将学习嵌入式应用中广泛使用的几种内存管理技术。本章涵盖的技术如下：

+   使用动态内存分配

+   探索对象池

+   使用环形缓冲区

+   使用共享内存

+   使用专用内存

这些技术将帮助您了解内存管理的最佳实践，并可在处理应用程序中的内存分配时用作构建块。

# 使用动态内存分配

动态内存分配是 C++开发人员常见的做法，在 C++标准库中被广泛使用；然而，在嵌入式系统的环境中，它经常成为难以发现和难以避免的问题的根源。

最显著的问题是时间。内存分配的最坏情况时间是不受限制的；然而，嵌入式系统，特别是那些控制真实世界进程或设备的系统，通常需要在特定时间内做出响应。

另一个问题是碎片化。当分配和释放不同大小的内存块时，会出现技术上是空闲的内存区域，但由于太小而无法分配给应用程序请求。内存碎片随着时间的推移而增加，可能导致内存分配请求失败，尽管总的空闲内存量相当大。

避免这类问题的一个简单而强大的策略是在编译时或启动时预先分配应用程序可能需要的所有内存。然后应用程序根据需要使用这些内存。一旦分配了这些内存，直到应用程序终止，就不会释放这些内存。

这种方法的缺点是应用程序分配的内存比实际使用的内存多，而不是让其他应用程序使用它。在实践中，这对于嵌入式应用来说并不是问题，因为它们在受控环境中运行，所有应用程序及其内存需求都是预先知道的。

# 如何做到...

在本技术中，我们将学习如何预先分配内存并在应用程序中使用它：

1.  在您的工作`〜/test`目录中，创建一个名为`prealloc`的子目录。

1.  使用您喜欢的文本编辑器在`prealloc`子目录中创建一个名为`prealloc.cpp`的文件。将以下代码片段复制到`prealloc.cpp`文件中以定义`SerialDevice`类：

```cpp
#include <cstdint>
#include <string.h>

constexpr size_t kMaxFileNameSize = 256;
constexpr size_t kBufferSize = 4096;
constexpr size_t kMaxDevices = 16;

class SerialDevice {
    char device_file_name[256];
    uint8_t input_buffer[kBufferSize];
    uint8_t output_buffer[kBufferSize];
    int file_descriptor;
    size_t input_length;
    size_t output_length;

  public:
    SerialDevice():
      file_descriptor(-1), input_length(0), output_length(0) {}

    bool Init(const char* name) {
      strncpy(device_file_name, name, sizeof(device_file_name));
    }

    bool Write(const uint8_t* data, size_t size) {
      if (size > sizeof(output_buffer)) {
        throw "Data size exceeds the limit";
      }
      memcpy(output_buffer, data, size);
    }

    size_t Read(uint8_t* data, size_t size) {
      if (size < input_length) {
        throw "Read buffer is too small";
      }
      memcpy(data, input_buffer, input_length);
      return input_length;
    }
};
```

1.  添加使用`SerialDevice`类的`main`函数：

```cpp
int main() {
  SerialDevice devices[kMaxDevices];
  size_t number_of_devices = 0;

  uint8_t data[] = "Hello";
  devices[0].Init("test");
  devices[0].Write(data, sizeof(data));
  number_of_devices = 1;

  return 0;
}
```

1.  在`loop`子目录中创建一个名为`CMakeLists.txt`的文件，内容如下：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(prealloc)
add_executable(prealloc prealloc.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++17")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

现在可以构建和运行应用程序。它不会输出任何数据，因为它的目的是演示我们如何预先分配内存，而不知道设备的数量和我们与设备交换的消息的大小。

# 工作原理...

在这个配方中，我们定义了封装与串行设备进行数据交换的对象。设备由可变长度的设备文件名字符串标识。我们可以向设备发送和接收可变长度的消息。

由于我们只能在运行时发现连接到系统的设备数量，我们可能会在发现时创建设备对象。同样，由于我们不知道发送和接收的消息大小，因此自然而然地要动态分配消息的内存。

相反，我们预分配未初始化设备对象的数组：

```cpp
  SerialDevice devices[kMaxDevices];
```

反过来，每个对象都预分配了足够的内存来存储消息和设备文件名：

```cpp
  char device_file_name[kMaxFileNameSize];
  uint8_t input_buffer[kBufferSize];
  uint8_t output_buffer[kBufferSize];
```

我们使用局部变量来跟踪输入和输出缓冲区中数据的实际大小。无需跟踪文件名的大小，因为预期它是以零结尾的：

```cpp
  size_t input_length;
  size_t output_length;
```

同样，我们跟踪实际发现的设备数量：

```cpp
  size_t number_of_devices = 0;
```

通过这种方式，我们避免了动态内存分配。尽管这样做有成本：我们人为地限制了支持的最大设备数量和消息的最大大小。其次，大量分配的内存从未被使用。例如，如果我们支持最多 16 个设备，而系统中只有 1 个设备，那么实际上我们只使用了分配内存的 1/16。如前所述，这对于嵌入式系统来说并不是问题，因为所有应用程序及其要求都是预定义的。没有应用程序可以从它可以分配的额外内存中受益。

# 探索对象池

正如我们在本章的第一个配方中讨论的那样，预分配应用程序使用的所有内存是一种有效的策略，有助于嵌入式应用程序避免与内存碎片化和分配时间相关的各种问题。

临时内存预分配的一个缺点是，应用程序现在负责跟踪预分配对象的使用情况。

对象池旨在通过提供类似于动态内存分配但使用预分配数组中的对象的泛化和便利接口来隐藏对象跟踪的负担。

# 如何做...

在这个配方中，我们将创建一个对象池的简单实现，并学习如何在应用程序中使用它：

1.  在您的工作`~/test`目录中，创建一个名为`objpool`的子目录。

1.  使用您喜欢的文本编辑器在`objpool`子目录中创建一个`objpool.cpp`文件。让我们定义一个模板化的`ObjectPool`类。我们从私有数据成员和构造函数开始：

```cpp
#include <iostream>

template<class T, size_t N>
class ObjectPool {
  private:
    T objects[N];
    size_t available[N];
    size_t top = 0;
  public:
    ObjectPool(): top(0) {
      for (size_t i = 0; i < N; i++) {
        available[i] = i;
      }
    }
```

1.  现在让我们添加一个从池中获取元素的方法：

```cpp
    T& get() {
      if (top < N) {
        size_t idx = available[top++];
        return objects[idx];
      } else {
        throw std::runtime_error("All objects are in use");
      }
    }
```

1.  接下来，我们添加一个将元素返回到池中的方法：

```cpp
    void free(const T& obj) {
      const T* ptr = &obj;
      size_t idx = (ptr - objects) / sizeof(T);
      if (idx < N) {
        if (top) {
          top--;
          available[top] = idx;
        } else {
          throw std::runtime_error("Some object was freed more than once");
        }
      } else {
        throw std::runtime_error("Freeing object that does not belong to
       the pool");
      }
     }
```

1.  然后，用一个小函数包装类定义，该函数返回从池中请求的元素数量：

```cpp
    size_t requested() const { return top; }
    };
```

1.  按照以下代码所示定义要存储在对象池中的数据类型：

```cpp
struct Point {
  int x, y;
};
```

1.  然后添加与对象池一起工作的代码：

```cpp
int main() {
  ObjectPool<Point, 10> points;

  Point& a = points.get();
  a.x = 10; a.y=20;
  std::cout << "Point a (" << a.x << ", " << a.y << ") initialized, requested "        <<
    points.requested() << std::endl;

  Point& b = points.get();
  std::cout << "Point b (" << b.x << ", " << b.y << ") not initialized, requested " <<
    points.requested() << std::endl;

  points.free(a);
  std::cout << "Point a(" << a.x << ", " << a.y << ") returned, requested " <<
    points.requested() << std::endl;

  Point& c = points.get();
  std::cout << "Point c(" << c.x << ", " << c.y << ") not intialized, requested " <<
    points.requested() << std::endl;

  Point local;
  try {
    points.free(local);
  } catch (std::runtime_error e) {
    std::cout << "Exception caught: " << e.what() << std::endl;
  }
  }
```

1.  在`loop`子目录中创建一个名为`CMakeLists.txt`的文件，内容如下：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(objpool)
add_executable(objpool objpool.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++11")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  构建应用程序并将生成的可执行二进制文件复制到目标系统。使用第二章中的配方，*设置环境*来完成。

1.  切换到目标系统终端。如果需要，使用用户凭据登录。

1.  运行二进制文件。

# 工作原理...

在这个应用程序中，我们使用了与第一个配方中相同的想法（预分配对象的静态数组），但是我们将其封装到一个模板化的`ObjectPool`类中，以提供处理不同类型对象的通用接口。

我们的模板有两个参数——存储在`ObjectPool`类实例中的对象的类或数据类型，以及池的大小。这些参数用于定义类的两个私有数据字段——对象数组和空闲索引数组：

```cpp
     T objects[N];
     size_t available[N];
```

由于模板参数在编译时被解析，这些数组是静态分配的。此外，该类有一个名为`top`的私有数据成员，它充当`available`数组中的索引，并指向下一个可用对象。

可用数组包含当前可用于使用的`objects`数组中所有对象的索引。在最开始，所有对象都是空闲的，并且可用数组中填充了对象数组中所有元素的索引：

```cpp
      for (size_t i = 0; i < N; i++) {
        available[i] = i;
      }
```

当应用程序需要从池中获取元素时，它调用`get`方法。该方法使用顶部变量来获取池中下一个可用元素的索引：

```cpp
      size_t idx = available[top++];
      return objects[idx];
```

当`top`索引达到数组大小时，意味着不能再分配更多元素，因此该方法会抛出异常以指示错误条件：

```cpp
      throw std::runtime_error("All objects are in use");
```

可以使用`free`将对象返回到池中。首先，它根据其地址检测元素的索引。索引被计算为对象地址与池起始地址的差异。由于池对象在内存中是连续存储的，我们可以轻松地过滤出相同类型的对象，但不能过滤出来自该池的对象：

```cpp
      const T* ptr = &obj;
      size_t idx = (ptr - objects) / sizeof(T);
```

请注意，由于`size_t`类型是无符号的，我们不需要检查结果索引是否小于零——这是不可能的。如果我们尝试将不属于池的对象返回到池中，并且其地址小于池的起始地址，它将被视为正索引。

如果我们返回的对象属于池，我们会更新顶部计数器，并将结果索引放入可用数组以供进一步使用：

```cpp
  top--;
  available[top] = idx;
```

否则，我们会抛出异常，指示我们试图返回一个不属于该池的对象：

```cpp
     throw std::runtime_error("Freeing object that does not belong to the pool");
```

所请求的方法用于跟踪池对象的使用情况。它返回顶部变量，该变量有效地跟踪已经被索取但尚未返回到池中的对象数量。

```cpp
     size_t requested() const { return top; }
```

让我们定义一个数据类型并尝试使用来自池的对象。我们声明一个名为`Point`的结构体，其中包含两个`int`字段，如下面的代码所示：

```cpp
 struct Point {
  int x, y;
 };
```

现在我们创建一个大小为`10`的`Point`对象池：

```cpp
    ObjectPool<Point, 10> points;
```

我们从池中获取一个对象并填充其数据字段：

```cpp
 Point& a = points.get();
 a.x = 10; a.y=20;
```

程序产生了以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/aac88c6f-a95e-44b3-8e8c-3173dac428a9.png)

输出的第一行报告了一个请求的对象。

我们请求了一个额外的对象并打印其数据字段，而不进行任何初始化。池报告说已经请求了两个对象，这是预期的。

现在我们将第一个对象返回到池中，并确保请求的对象数量减少。我们还可以注意到，即使将对象返回到池中，我们仍然可以从中读取数据。

让我们从池中再索取一个对象。请求的数量增加，但请求的对象与我们在上一步中返回的对象相同。

我们可以看到`Point c`在从池中取出后没有被初始化，但其字段包含与`Point a`相同的值。实际上，现在`a`和`c`是对池中相同对象的引用，因此对变量`a`的修改将影响变量`c`。这是我们对象池实现的一个限制。

最后，我们创建一个本地的`Point`对象并尝试将其返回到池中：

```cpp
  Point local;
  try {
    points.free(local);
  } catch (std::runtime_error e) {
    std::cout << "Exception caught: " << e.what() << std::endl;
  }
```

预计会出现异常，并且确实如此。在程序输出中，您可以看到一个`Exception caught: Freeing object that does not belong to the pool`的消息。

# 还有更多...

尽管对象池的实现简化了与预分配对象的工作，但它有许多限制。

首先，所有对象都是在最开始创建的。因此，调用我们的池的`get`方法不会触发对象构造函数，调用`free`方法也不会调用析构函数。开发人员需要使用各种变通方法来初始化和去初始化对象。

一个可能的解决方法是定义目标对象的特殊方法，比如`initialize`和`deinitialize`，分别由`ObjectPool`类的`get`和`free`方法调用。然而，这种方法将类的实现与`ObjectPool`的实现耦合在一起。在本章的后面，我们将看到更高级的技术来克服这个限制。

我们的池的实现没有检测`free`方法是否对一个对象调用了多次。这是一个错误，但是很常见，并导致难以调试的问题。虽然在技术上是可行的，但它给实现增加了不必要的额外复杂性。

# 使用环形缓冲区

环形缓冲区，或循环缓冲区，在嵌入式世界中是一个广泛使用的数据结构。它作为一个队列放置在固定大小的内存数组之上。缓冲区可以包含固定数量的元素。生成这些元素的函数将它们顺序放入缓冲区中。当达到缓冲区的末尾时，它会切换到缓冲区的开头，就好像它的第一个元素跟在最后一个元素后面。

当涉及到组织数据生产者和消费者之间的数据交换时，这种设计被证明是非常高效的，因为它们是独立的，不能等待对方，这在嵌入式开发中是常见的情况。例如，中断服务例程应该快速地将来自设备的数据排队等待进一步处理，而中断被禁用。如果处理数据的函数落后，它不能等待中断服务例程。同时，处理函数不需要完全与**中断服务例程**（**ISR**）同步；它可以一次处理多个元素，并在稍后赶上 ISR。

这个特性，以及它们可以在静态情况下预先分配，使得环形缓冲区在许多情况下成为最佳选择。

# 如何做...

在这个示例中，我们将学习如何在 C++数组之上创建和使用环形缓冲区：

1.  在您的工作`~/test`目录中，创建一个名为`ringbuf`的子目录。

1.  使用您喜欢的文本编辑器在`ringbuf`子目录中创建一个`ringbuf.cpp`文件。

1.  从`private`数据字段开始定义`RingBuffer`类。

```cpp
#include <iostream>

template<class T, size_t N>
class RingBuffer {
  private:
    T objects[N];
    size_t read;
    size_t write;
    size_t queued;
  public:
    RingBuffer(): read(0), write(0), queued(0) {}
```

1.  现在我们添加一个将数据推送到缓冲区的方法：

```cpp
    T& push() {
      T& current = objects[write];
      write = (write + 1) % N;
      queued++;
      if (queued > N) {
        queued = N;
        read = write;
      }
      return current;
    }

```

1.  接下来，我们添加一个从缓冲区中拉取数据的方法：

```cpp
    const T& pull() {
      if (!queued) {
        throw std::runtime_error("No data in the ring buffer");
      }
      T& current = objects[read];
      read = (read + 1) % N;
      queued--;
      return current;
    }
```

1.  让我们添加一个小方法来检查缓冲区是否包含任何数据，并完成类的定义：

```cpp
bool has_data() {
  return queued != 0;
}
};
```

1.  有了`RingBuffer`的定义，我们现在可以添加使用它的代码了。首先，让我们定义我们将要使用的数据类型：

```cpp
struct Frame {
  uint32_t index;
  uint8_t data[1024];
};
```

1.  其次，添加`main`函数，并定义`RingBuffer`的一个实例作为其变量，以及尝试使用空缓冲区的代码：

```cpp
int main() {
  RingBuffer<Frame, 10> frames;

  std::cout << "Frames " << (frames.has_data() ? "" : "do not ")
      << "contain data" << std::endl;
  try {
    const Frame& frame = frames.pull();
  } catch (std::runtime_error e) {
    std::cout << "Exception caught: " << e.what() << std::endl;
  }
```

1.  接下来，添加使用缓冲区中五个元素的代码：

```cpp
for (size_t i = 0; i < 5; i++) {
Frame& out = frames.push();
out.index = i;
out.data[0] = 'a' + i;
out.data[1] = '\0';
  }
std::cout << "Frames " << (frames.has_data() ? "" : "do not ")
<< "contain data" << std::endl;
while (frames.has_data()) {
const Frame& in = frames.pull();
    std::cout << "Frame " << in.index << ": " << in.data << std::endl;
  }
```

1.  之后，添加类似的代码，处理可以添加的更多元素的情况：

```cpp
    for (size_t i = 0; i < 26; i++) {
    Frame& out = frames.push();
    out.index = i;
    out.data[0] = 'a' + i;
    out.data[1] = '\0';
    }
    std::cout << "Frames " << (frames.has_data() ? "" : "do not ")
      << "contain data" << std::endl;
    while (frames.has_data()) {
    const Frame& in = frames.pull();
    std::cout << "Frame " << in.index << ": " << in.data << std::endl;
    }
    }
```

1.  在`loop`子目录中创建一个名为`CMakeLists.txt`的文件，内容如下：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(ringbuf)
add_executable(ringbuf ringbuf.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++11")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  构建应用程序，并将生成的可执行二进制文件复制到目标系统。使用第二章中的示例，*设置环境*。

1.  切换到目标系统终端。如果需要，使用用户凭据登录。

1.  运行二进制文件。

# 它是如何工作的...

我们将我们的环形缓冲区实现为一个模板化的 C++类，它有三个私有数据字段：

+   `objects`: 类型为`T`的`N`个元素的静态数组

+   `read`: 一个用于读取元素的索引

+   `write`: 用于写入元素的索引

`RingBuffer`类公开了三个公共方法：

+   `push()`: 将数据写入缓冲区

+   `pull()`: 从缓冲区中读取数据

+   `has_data()`: 检查缓冲区是否包含数据

让我们仔细看看它们是如何工作的。

`push()`方法旨在被函数用于将数据存储在缓冲区中。与动态队列或动态栈的类似`push()`方法不同，后者接受一个要存储的值作为参数，我们的实现不接受任何参数。由于所有元素在编译时都是预分配的，它返回对要更新的缓冲区中的值的引用。

`push()`方法的实现很简单；它通过`write`索引获取对元素的指针，然后推进`write`索引并增加存储在缓冲区中的元素数量。请注意，取模运算符用于在`write`索引达到大小限制时将其包装到数组的开头：

```cpp
T& current = objects[write];
write = (write + 1) % N;
queued++;
```

如果我们尝试推送的元素数量超过`objects`数组的容量处理能力会发生什么？这取决于我们计划存储在缓冲区中的数据的性质。在我们的实现中，我们假设接收方对最近的数据感兴趣，并且如果它无法赶上发送方，则可以容忍中间数据的丢失。如果接收方太慢，那么在接收方`read`数据之前发送方运行了多少圈都无所谓：在这一点上超过`N`步的所有数据都被覆盖。这就是为什么一旦存储的元素数量超过`N`，我们开始推进`read`索引以及`write`索引，使它们确切地相隔`N`步：

```cpp
 if (queued > N) {
  queued = N;
  read = write;
 }
```

`pull()`方法由从缓冲区读取数据的函数使用。与`push()`方法类似，它不接受任何参数，并返回对缓冲区中元素的引用。不过，与`push()`方法不同的是，它返回一个常量引用（如下面的代码所示），以表明它不应该修改缓冲区中的数据：

```cpp
 const T& pull() {
```

首先，它检查缓冲区中是否有数据，并且如果缓冲区不包含元素，则抛出异常：

```cpp
  if (!queued) {
   throw std::runtime_error("No data in the ring buffer");
  }
```

它通过读取索引获取对元素的引用，然后推进`read`索引，应用与`push()`方法为`write`索引所做的相同的取模运算符：

```cpp
  read = (read + 1) % N;
  queued--;
```

`has_data()`方法的实现是微不足道的。如果对象计数为零，则返回`false`，否则返回`true`：

```cpp
  bool has_data() {
  return queued != 0;
  }
```

现在，让我们尝试实际操作。我们声明一个简单的数据结构`Frame`，模拟设备生成的数据。它包含一个帧索引和一个不透明的数据缓冲区：

```cpp
  uint32_t index;
  uint8_t data[1024];
  };
```

我们定义了一个容量为`10`个`frame`类型元素的环形缓冲区：

```cpp
  RingBuffer<Frame, 10> frames;
```

让我们来看看程序的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/45ab92d8-96c5-42ce-aee0-b49bd991217a.png)

首先，我们尝试从空缓冲区中读取并得到一个异常，这是预期的。

然后，我们将五个元素写入缓冲区，使用拉丁字母表的字符作为数据载荷：

```cpp
  for (size_t i = 0; i < 5; i++) {
    Frame& out = frames.push();
    out.index = i;
    out.data[0] = 'a' + i;
    out.data[1] = '\0';
  }
```

注意我们如何获取对元素的引用，然后在原地更新它，而不是将`frame`的本地副本推入环形缓冲区。然后我们读取缓冲区中的所有数据并将其打印在屏幕上：

```cpp
  while (frames.has_data()) {
    const Frame& in = frames.pull();
    std::cout << "Frame " << in.index << ": " << in.data << std::endl;
  }
```

程序输出表明我们可以成功读取所有五个元素。现在我们尝试将拉丁字母表的所有 26 个字母写入数组，远远超过其容量。

```cpp
 for (size_t i = 0; i < 26; i++) {
    Frame& out = frames.push();
    out.index = i;
    out.data[0] = 'a' + i;
    out.data[1] = '\0';
  }
```

然后我们以与五个元素相同的方式读取数据。读取是成功的，但我们只收到了最后写入的 10 个元素；所有其他帧都已丢失并被覆盖。对于我们的示例应用程序来说这并不重要，但对于许多其他应用程序来说可能是不可接受的。确保数据不会丢失的最佳方法是保证接收方的激活频率高于发送方。有时，如果缓冲区中没有可用数据，接收方将被激活，但这是为了避免数据丢失而可以接受的代价。

# 使用共享内存

在运行在支持**MMU**（内存管理单元）的硬件上的现代操作系统中，每个应用程序作为一个进程运行，并且其内存与其他应用程序隔离。

这种隔离带来了重要的可靠性优势。一个应用程序不能意外地破坏另一个应用程序的内存。同样，一个意外破坏自己内存并崩溃的应用程序可以被操作系统关闭，而不会影响系统中的其他应用程序。将嵌入式系统的功能解耦为几个相互通信的隔离应用程序，通过一个明确定义的 API 显著减少了实现的复杂性，从而提高了稳定性。

然而，隔离会产生成本。由于每个进程都有自己独立的地址空间，两个应用程序之间的数据交换意味着数据复制、上下文切换和使用操作系统内核同步机制，这可能是相对昂贵的。

共享内存是许多操作系统提供的一种机制，用于声明某些内存区域为共享。这样，应用程序可以在不复制数据的情况下交换数据。这对于交换大型数据对象（如视频帧或音频样本）尤为重要。

# 如何做...

在这个示例中，我们将学习如何使用 Linux 共享内存 API 在两个或多个应用程序之间进行数据交换。

1.  在您的工作`~/test`目录中，创建一个名为`shmem`的子目录。

1.  使用您喜欢的文本编辑器在`shmem`子目录中创建一个`shmem.cpp`文件。从常见的头文件和常量开始定义`SharedMem`类：

```cpp
#include <algorithm>
#include <iostream>
#include <chrono>
#include <thread>

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

const char* kSharedMemPath = "/sample_point";
const size_t kPayloadSize = 16;

using namespace std::literals;

template<class T>
class SharedMem {
  int fd;
  T* ptr;
  const char* name;

  public:
```

1.  然后，定义一个大部分工作的构造函数：

```cpp
SharedMem(const char* name, bool owner=false) {
fd = shm_open(name, O_RDWR | O_CREAT, 0600);
if (fd == -1) {
throw std::runtime_error("Failed to open a shared memory region");
}
if (ftruncate(fd, sizeof(T)) < 0) {
close(fd);
throw std::runtime_error("Failed to set size of a shared memory 
region");
};
ptr = (T*)mmap(nullptr, sizeof(T), PROT_READ | PROT_WRITE, 
MAP_SHARED, fd, 0);
if (!ptr) {
close(fd);
    throw std::runtime_error("Failed to mmap a shared memory region");
}
    this->name = owner ? name : nullptr;
    std::cout << "Opened shared mem instance " << name << std::endl;
}
```

1.  添加析构函数的定义：

```cpp
    ~SharedMem() {
      munmap(ptr, sizeof(T));
      close(fd);
      if (name) {
        std::cout << "Remove shared mem instance " << name << std::endl;
        shm_unlink(name);
      }
      }
```

1.  用一个小方法来完成类定义，返回一个对共享对象的引用：

```cpp
    T& get() const {
      return *ptr;
    }
    };
```

1.  我们的`SharedMem`类可以处理不同的数据类型。让我们声明一个自定义数据结构，我们想要使用：

```cpp
struct Payload {
  uint32_t index;
  uint8_t raw[kPayloadSize];
};
```

1.  现在添加代码，将数据写入共享内存：

```cpp
void producer() {
  SharedMem<Payload> writer(kSharedMemPath);
  Payload& pw = writer.get();
  for (int i = 0; i < 5; i++) {
    pw.index = i;
    std::fill_n(pw.raw, sizeof(pw.raw) - 1, 'a' + i);
    pw.raw[sizeof(pw.raw) - 1] = '\0';
    std::this_thread::sleep_for(150ms);
  }
}
```

1.  还要添加从共享内存中读取数据的代码：

```cpp
void consumer() {
  SharedMem<Payload> point_reader(kSharedMemPath, true);
  Payload& pr = point_reader.get();
  for (int i = 0; i < 10; i++) {
    std::cout << "Read data frame " << pr.index << ": " << pr.raw << std::endl;
    std::this_thread::sleep_for(100ms);
  }
  }
```

1.  添加`main`函数，将所有内容联系在一起，如下面的代码所示：

```cpp
int main() {

  if (fork()) {
    consumer();
  } else {
    producer();
  }
  }
```

1.  在`loop`子目录中创建一个名为`CMakeLists.txt`的文件，内容如下：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(shmem)
add_executable(shmem shmem.cpp)
target_link_libraries(shmem rt)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++14")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  构建应用程序，并将生成的可执行二进制文件复制到目标系统。使用第二章中的设置环境的方法来完成。

1.  切换到目标系统终端。如果需要，使用用户凭据登录。

1.  运行二进制文件。

# 它是如何工作的...

在这个示例中，我们使用**POSIX**（**可移植操作系统接口**的缩写）API 来处理共享内存。这是一个灵活和细粒度的 C API，有很多可以调整或配置的参数。我们的目标是通过在其上实现一个更方便和类型安全的 C++包装器来隐藏这个低级 API 的复杂性。我们将使用**RAII**（**资源获取即初始化**的缩写）习惯，以确保所有分配的资源都得到适当的释放，我们的应用程序中没有内存或文件描述符泄漏。

我们定义了一个模板化的`SharedMem`类。模板参数定义了存储在我们的共享内存实例中的数据类型。这样，我们使`SharedMem`类的实例类型安全。我们不再需要在应用程序代码中使用 void 指针和类型转换，C++编译器会自动为我们完成：

```cpp
template<class T>
class SharedMem {
```

所有共享内存分配和初始化都在`SharedMem`构造函数中实现。它接受两个参数：

+   一个共享内存对象名称

+   一个所有权标志

POSIX 定义了一个`shm_open`API，其中共享内存对象由名称标识，类似于文件名。这样，使用相同名称的两个独立进程可以引用相同的共享内存对象。共享对象的生命周期是什么？当为相同的对象名称调用`shm_unlink`函数时，共享对象被销毁。如果对象被多个进程使用，第一个调用`shm_open`的进程将创建它，其他进程将重用相同的对象。但是它们中的哪一个负责删除它？这就是所有权标志的用途。当设置为`true`时，它表示`SharedMem`实例在销毁时负责共享对象的清理。

构造函数依次调用三个 POSIX API 函数。首先，它使用`shm_open`创建一个共享对象。虽然该函数接受访问标志和文件权限作为参数，但我们总是使用读写访问模式和当前用户的读写访问权限：

```cpp
fd = shm_open(name, O_RDWR | O_CREAT, 0600);
```

接下来，我们使用`ftruncate`调用定义共享区域的大小。我们使用模板数据类型的大小来实现这个目的：

```cpp
if (ftruncate(fd, sizeof(T)) < 0) {
```

最后，我们使用`mmap`函数将共享区域映射到我们的进程内存地址空间。它返回一个指针，我们可以用来引用我们的数据实例：

```cpp
ptr = (T*)mmap(nullptr, sizeof(T), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
```

该对象将文件描述符和内存区域的指针保存为其私有成员。析构函数在对象被销毁时对它们进行释放。如果设置了所有者标志，我们还保留对象名称，以便我们可以删除它：

```cpp
int fd;
T* ptr;
const char* name;
```

`SharedMem`析构函数将共享内存对象从地址空间中取消映射：

```cpp
 munmap(ptr, sizeof(T));
```

如果对象是所有者，我们可以使用`shm_unlink`调用来删除它。请注意，自从名称设置为`nullptr`后，我们不再需要所有者标志，除非对象是所有者：

```cpp
 if (name) {
   std::cout << "Remove shared mem instance " << name << std::endl;
 shm_unlink(name);
 }
```

为了访问共享数据，该类提供了一个简单的`get`方法。它返回存储在共享内存中的对象的引用：

```cpp
  T& get() const {
      return *ptr;
  }
```

让我们创建两个使用我们创建的共享内存 API 的独立进程。我们使用 POSIX 的`fork`函数来生成一个子进程。子进程将是数据生产者，父进程将是数据消费者：

```cpp
  if (fork()) {
    consumer();
  } else {
    producer();
  }
```

我们定义了一个`Payload`数据类型，生产者和消费者都用于数据交换：

```cpp
  struct Payload {
  uint32_t index;
  uint8_t raw[kPayloadSize];
  };
```

数据生产者创建一个`SharedMem`实例：

```cpp
  SharedMem<Payload> writer(kSharedMemPath);
```

它使用`get`方法接收的引用每 150 毫秒更新一次共享对象。每次，它增加有效载荷的索引字段，并用与索引匹配的拉丁字母填充其数据。

消费者和生产者一样简单。它创建一个与生产者同名的`SharedMem`实例，但它声明了对该对象的所有权。这意味着它将负责删除它，如下面的代码所示：

```cpp
  SharedMem<Payload> point_reader(kSharedMemPath, true);
```

运行应用程序并观察以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/714b3428-c62d-4794-b090-b8a3bd2a72ee.png)

每 100 毫秒，应用程序从共享对象中读取数据并将其打印到屏幕上。在消费者输出中，我们可以看到它接收到了生产者写入的数据。由于消费者和生产者周期的持续时间不匹配，我们可以看到有时相同的数据被读取两次

在这个例子中故意省略的逻辑的一个重要部分是生产者和消费者的同步。由于它们作为独立的项目运行，不能保证生产者在消费者尝试读取数据时已经更新了任何数据。以下是我们在结果输出中看到的内容：

```cpp
Opened shared mem instance /sample_point
Read data frame 0: 
Opened shared mem instance /sample_point
```

我们可以看到，在生产者打开相同的对象之前，消费者打开了共享内存对象并读取了一些数据。

同样，当消费者尝试读取数据时，无法保证生产者是否完全更新数据字段。我们将在下一章中更详细地讨论这个话题。

# 还有更多...

共享内存本身是一种快速高效的进程间通信机制，但当与环形缓冲区结合时，它真正发挥作用。通过将环形缓冲区放入共享内存中，开发人员可以允许独立的数据生产者和数据消费者异步交换数据，并且同步的开销很小。

# 使用专用内存

嵌入式系统通常通过特定的内存地址范围提供对其外围设备的访问。当程序访问这个区域中的地址时，它不会读取或写入内存中的值。相反，数据被发送到该地址映射的设备或从该设备读取。

这种技术通常被称为**MMIO**（内存映射输入/输出）。在这个教程中，我们将学习如何从用户空间的 Linux 应用程序中使用 MMIO 访问 Raspberry PI 的外围设备。

# 如何做...

Raspberry PI 有许多外围设备可以通过 MMIO 访问。为了演示 MMIO 的工作原理，我们的应用程序将访问系统定时器：

1.  在您的工作`~/test`目录中，创建一个名为`timer`的子目录。

1.  使用您最喜欢的文本编辑器在`timer`子目录中创建名为`timer.cpp`的文件。

1.  将所需的头文件、常量和类型声明放入`timer.cpp`中：

```cpp
#include <iostream>
#include <chrono>
#include <system_error>
#include <thread>

#include <fcntl.h>
#include <sys/mman.h>

constexpr uint32_t kTimerBase = 0x3F003000;

struct SystemTimer {
  uint32_t CS;
  uint32_t counter_lo;
  uint32_t counter_hi;
};
```

1.  添加`main`函数，其中包含程序的所有逻辑：

```cpp
int main() {

  int memfd = open("/dev/mem", O_RDWR | O_SYNC);
  if (memfd < 0) {
  throw std::system_error(errno, std::generic_category(),
  "Failed to open /dev/mem. Make sure you run as root.");
  }

  SystemTimer *timer = (SystemTimer*)mmap(NULL, sizeof(SystemTimer),
  PROT_READ|PROT_WRITE, MAP_SHARED,
  memfd, kTimerBase);
  if (timer == MAP_FAILED) {
  throw std::system_error(errno, std::generic_category(),
  "Memory mapping failed");
  }

  uint64_t prev = 0;
  for (int i = 0; i < 10; i++) {
   uint64_t time = ((uint64_t)timer->counter_hi << 32) + timer->counter_lo;
   std::cout << "System timer: " << time;
   if (i > 0) {
   std::cout << ", diff " << time - prev;
    }
    prev = time;
    std::cout << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return 0;
 }
```

1.  在`timer`子目录中创建一个名为`CMakeLists.txt`的文件，并包含以下内容：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(timer)
add_executable(timer timer.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++11")

set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  现在可以构建和运行应用程序了。

请注意，它应该在真正的 Raspberry PI 3 设备上以`root`身份运行。

# 它是如何工作的...

系统定时器是一个外围设备，通过 MMIO 接口连接到处理器。这意味着它有一系列专用的物理地址，每个地址都有特定的格式和用途。

我们的应用程序使用两个 32 位值表示的计时器计数器。组合在一起，它们形成一个 64 位的只读计数器，在系统运行时始终递增。

对于 Raspberry PI 3，为系统定时器分配的物理内存地址范围的偏移量为`0x3F003000`（根据 Raspberry PI 硬件版本的不同可能会有所不同）。我们将其定义为一个常量。

```cpp
constexpr uint32_t kTimerBase = 0x3F003000;
```

为了访问区域内的各个字段，我们定义了一个`SystemTimer`结构：

```cpp
struct SystemTimer {
  uint32_t CS;
  uint32_t counter_lo;
  uint32_t counter_hi;
};
```

现在，我们需要获取指向定时器地址范围的指针，并将其转换为指向`SystemTimer`的指针。这样，我们就可以通过读取`SystemTimer`的数据字段来访问计数器的地址。

然而，我们需要解决一个问题。我们知道物理地址空间中的偏移量，但我们的 Linux 应用程序在虚拟地址空间中运行。我们需要找到一种将物理地址映射到虚拟地址的方法。

Linux 通过特殊的`/proc/mem`文件提供对物理内存地址的访问。由于它包含所有物理内存的快照，因此只能由`root`访问。

我们使用`open`函数将其作为常规文件打开：

```cpp
int memfd = open("/dev/mem", O_RDWR | O_SYNC);
```

一旦文件打开并且我们知道它的描述符，我们就可以将其映射到我们的虚拟地址空间中。我们不需要映射整个物理内存。与定时器相关的区域就足够了，这就是为什么我们将系统定时器范围的起始位置作为偏移参数传递，将`SystemTimer`结构的大小作为大小参数传递：

```cpp
SystemTimer *timer = (SystemTimer*)mmap(NULL, sizeof(SystemTimer),
PROT_READ|PROT_WRITE, MAP_SHARED, memfd, kTimerBase);
```

现在我们可以访问定时器字段了。我们在循环中读取定时器计数器，并显示其当前值及其与前一个值的差异。当我们以`root`身份运行我们的应用程序时，我们会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/aa941e90-c2ed-49d6-a79c-c813bc3b95aa.png)

正如我们所看到的，从这个内存地址读取返回递增的值。差值的值大约为 10,000，而且非常恒定。由于我们在计数器读取循环中添加了 10 毫秒的延迟，我们可以推断这个内存地址与定时器相关，而不是常规内存，定时器计数器的粒度为 1 微秒。

# 还有更多...

树莓派有许多外围设备可以通过 MMIO 访问。您可以在*BCM2835 ARM 外围设备手册*中找到关于它们的地址范围和访问语义的详细信息，该手册可在[`www.raspberrypi.org/documentation/hardware/raspberrypi/bcm2835/BCM2835-ARM-Peripherals.pdf`](https://www.raspberrypi.org/documentation/hardware/raspberrypi/bcm2835/BCM2835-ARM-Peripherals.pdf)上找到。

请注意，开发人员在处理可以同时被多个设备访问的内存时必须非常小心。当内存可以被多个处理器或同一处理器的多个核心访问时，您可能需要使用高级同步技术，如内存屏障，以避免同步问题。我们将在下一章讨论其中一些技术。如果您使用直接内存访问（DMA）或 MMIO，情况会变得更加复杂。由于 CPU 可能不知道内存被外部硬件更改，其缓存可能不同步，导致数据一致性问题。
