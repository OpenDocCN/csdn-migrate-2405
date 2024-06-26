# C++ 现代嵌入式编程秘籍（六）

> 原文：[`annas-archive.org/md5/5f729908f617ac4c3bf4b93d739754a8`](https://annas-archive.org/md5/5f729908f617ac4c3bf4b93d739754a8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章：微控制器编程

在之前的章节中，我们大多涵盖了适用于具有兆字节内存并运行 Linux 操作系统的相对强大的嵌入式系统的主题。现在，我们将探索嵌入式系统光谱的另一面——微控制器。

正如我们在介绍中讨论的那样，微控制器通常用于执行简单的、通常是实时的任务，比如收集数据或为特定设备提供高级 API。微控制器价格低廉，能耗低，可以在各种环境条件下工作，因此是物联网应用的理想选择。

他们低成本的另一面是他们的能力。通常，它们具有以千字节为单位的内置存储器，没有硬件内存映射。它们根本不运行任何操作系统，或者运行像 FreeRTOS 这样的简单实时操作系统。

有许多型号的微控制器，专为特定应用而设计。在本章中，我们将学习如何使用 Arduino 开发环境。这些配方是为基于 ATmega328 微控制器的 Arduino UNO 板创建的，该板广泛用于教育和原型开发，但它们也适用于其他 Arduino 板。

我们将涵盖以下主题：

+   搭建开发环境

+   编译和上传程序

+   调试微控制器代码

这些配方将帮助您设置环境并开始为微控制器开发。

# 搭建开发环境

Arduino UNO 板配备了一个名为 Arduino IDE 的集成开发环境，可以从[`www.arduino.cc/`](https://www.arduino.cc/)[网站](https://www.arduino.cc/)免费下载。

在这个配方中，我们将学习如何设置并连接您的 Arduino 板。

# 如何做...

我们将安装 Arduino IDE，将 Arduino UNO 板连接到计算机，然后在 IDE 和板之间建立通信：

1.  在浏览器中打开下载页面（[`www.arduino.cc/en/Main/Software`](https://www.arduino.cc/en/Main/Software)），选择与您的操作系统匹配的安装选项。

1.  下载完成后，按照*入门*（[`www.arduino.cc/en/Guide/HomePage`](https://www.arduino.cc/en/Guide/HomePage)）页面上的安装说明进行操作。

1.  使用 USB 电缆将您的 Arduino 板连接到计算机上，它将自动上电。

1.  运行 Arduino IDE。

1.  现在，我们需要在 IDE 和板之间建立通信。切换到 Arduino IDE 窗口。在应用程序菜单中，选择“工具”->“端口”。这将打开一个子菜单，显示可用的串行端口选项。选择带有 Arduino 名称的端口。

1.  在“工具”菜单中，点击“板”项目，然后选择您的 Arduino 板型号。

1.  选择“工具”->“板信息”菜单项。

# 工作原理...

Arduino 板配备了一个免费的 IDE，可以从制造商的网站下载。IDE 的安装很简单，与为您的平台安装任何其他软件没有区别。

所有代码都是在 IDE 中编写、编译和调试的，但生成的编译图像应该被刷到目标板上并在那里执行。为此，IDE 应该能够与板进行通信。

该板通过 USB 连接到运行 IDE 的计算机。USB 电缆不仅提供通信，还为板提供电源。一旦板连接到计算机，它就会打开并开始工作。

IDE 使用串行接口与板进行通信。由于您的计算机上可能已经配置了多个串行端口，设置通信的步骤之一是选择其中一个可用的端口。通常，它是带有 Arduino 名称的端口：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/c1a46111-aa64-40fa-8b02-89e6f0e44b6c.png)

最后，一旦选择了端口，我们让 IDE 知道我们使用的 Arduino 板的类型。完成后，我们可以检查板和 IDE 之间的通信是否实际有效。当我们调用 Board Info 菜单项时，IDE 会显示一个包含有关连接板的信息的对话框窗口：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/16acebfc-27e7-4597-9f52-8beceb7b0020.png)

如果对话框没有显示，这表示存在问题。板可能已断开连接或损坏，或者可能选择了错误的端口。否则，我们准备构建和运行我们的第一个程序。

# 还有更多...

如果出现问题，请考虑阅读 Arduino 网站上的故障排除部分（[`www.arduino.cc/en/Guide/Troubleshooting`](https://www.arduino.cc/en/Guide/Troubleshooting)）。

# 编译和上传程序

在上一个步骤中，我们学习了如何设置开发环境。现在，让我们编译和运行我们的第一个程序。

Arduino UNO 板本身没有屏幕，但我们需要一种方式来知道我们的程序正在做些什么。但是，它确实有一个内置 LED，我们可以在不连接任何外围设备到板上的情况下从我们的程序中控制。

在这个步骤中，我们将学习如何编译和运行一个在 Arduino UNO 板上闪烁内置 LED 的程序。

# 如何做...

我们将编译并上传到板上一个已经存在的 IDE 自带的示例应用程序：

1.  将 Arduino 板连接到计算机并打开 Arduino IDE。

1.  在 Arduino IDE 中，打开文件菜单，选择示例-> 01\.基础-> 闪烁。

1.  将打开一个新窗口。在此窗口中，单击上传按钮。

1.  观察板上的内置 LED 开始闪烁。

# 它是如何工作的...

Arduino 是一个广泛用于教育目的的平台。它设计成易于使用，并附带一堆示例。对于我们的第一个程序，我们选择了一个不需要将板与外部设备连接的应用程序。一旦启动 IDE，我们从可用的示例中选择了 Blink 应用程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/9c4aa898-0a41-4617-b54b-6bee11bd551f.png)

这将打开一个带有程序代码的窗口：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/e5b18011-15bc-4c0e-aed8-d2f26799737d.png)

除了程序的源代码外，我们还可以看到一个黑色控制台窗口和状态栏，指示 Arduino UNO 板通过`/dev/cu.usbmodem14101`串行端口连接。设备名称取决于板型号，端口名称在 Windows 或 Linux 中可能看起来不同。

在源代码上方，我们可以看到几个按钮。第二个按钮是上传按钮。按下后，IDE 开始构建应用程序，然后将生成的二进制文件上传到板上。我们可以在控制台窗口中看到构建状态：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/d0a8e609-5449-4491-866d-7708f48e4f68.png)

上传后立即启动应用程序。如果我们看看板，我们可以看到内置的黄色 LED 已经开始闪烁。我们成功构建并运行了我们的第一个 Arduino 应用程序。

# 还有更多...

上传后，程序将存储在板上的闪存内存中。如果关闭板电源然后再次打开，即使没有运行 IDE，程序也会开始运行。

# 调试微控制器代码

与树莓派等更强大的嵌入式平台相比，Arduino 的调试能力有限。Arduino IDE 不提供集成调试器，Arduino 板本身也没有内置屏幕。但是，它确实具有 UART，并提供可用于调试目的的串行接口。

在这个步骤中，我们将学习如何使用 Arduino 串行接口进行调试和读取用户输入。

# 如何做...

我们将为 Arduino 控制器实现一个简单的程序，该程序在串行端口上等待用户输入，并根据数据打开或关闭内置 LED：

1.  打开 Arduino IDE 并在其文件菜单中选择新建。将显示一个新的 Sketch 窗口。

1.  将以下代码片段粘贴到 Sketch 窗口中：

```cpp
void setup() {
 pinMode(LED_BUILTIN, OUTPUT);
 Serial.begin(9600);
 while (!Serial);
}

void loop() {
  if (Serial.available() > 0) {
      int inByte = Serial.read();
      if (inByte == '1') {
        Serial.print("Turn LED on\n");
        digitalWrite(LED_BUILTIN, HIGH);
      } else if (inByte == '0') {
        Serial.print("Turn LED off\n");
        digitalWrite(LED_BUILTIN, LOW); 
      } else {
        Serial.print("Ignore byte ");
        Serial.print(inByte);
        Serial.print("\n");
      }
      delay(500);
  }
}
```

1.  单击“上传”按钮以构建和运行代码。

1.  在 Arduino IDE 的工具菜单中选择串行监视器。串行监视器窗口将出现。

1.  在串行监视器窗口中，输入 `1010110`。

# 工作原理...

我们创建一个由两个函数组成的新的 Arduino 草图。第一个函数 `setup` 在程序启动时被调用，并用于提供应用程序的初始配置。

在我们的情况下，我们需要初始化串行接口。串行通信的最重要参数是每秒位数的速度。微控制器和 IDE 都应同意使用相同的速度，否则通信将无法工作。串行监视器默认使用每秒 9,600 位，我们在程序中使用这个值：

```cpp
Serial.begin(9600);
```

虽然可以使用更高的通信速度。串行监视器在屏幕右下角有一个下拉菜单，允许选择其他速度。如果决定使用其他速度，则应相应修改代码。

我们还为输出配置引脚 13，对应于内置 LED：

```cpp
pinMode(LED_BUILTIN, OUTPUT);
```

我们使用常量 `LED_BUILTIN`，而不是 `13`，以使代码更易理解。第二个函数 `loop` 定义了 Arduino 程序的无限循环。对于每次迭代，我们从串行端口读取一个字节：

```cpp
if (Serial.available() > 0) {
      int inByte = Serial.read();
```

如果字节是 `1`，我们打开 LED 并向串行端口写入一条消息：

```cpp
        Serial.print("Turn LED on\n");
        digitalWrite(LED_BUILTIN, HIGH);
```

同样地，对于 `0`，我们关闭 LED：

```cpp
        Serial.print("Turn LED off\n");
        digitalWrite(LED_BUILTIN, LOW); 
```

所有其他值都被忽略。在从端口读取每个字节后，我们添加 500 微秒的延迟。这样，我们可以定义不同的闪烁模式。例如，如果我们发送 `1001001`，LED 将在 0.5 秒内打开，然后在 1 秒内关闭，再在 0.5 秒内打开，再在 1 秒内关闭，最后再次打开。

如果我们运行代码并在串行监视器中输入 `1001001`，我们可以看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/6d2f169e-1b5f-4686-8942-7f5faf28a277.png)

LED 正如预期地闪烁，并且除此之外，我们可以在串行监视器中看到调试消息。通过这种方式，我们可以调试真实的、更复杂的应用程序。
