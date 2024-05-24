# C++ 游戏开发的音频编程入门指南（一）

> 原文：[`zh.annas-archive.org/md5/DA6F8DEA921C8862289A88F7D7BB3BD8`](https://zh.annas-archive.org/md5/DA6F8DEA921C8862289A88F7D7BB3BD8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

音频在视频游戏中无疑是我们手头最强大的工具之一，它可以在许多不同的方面发挥作用，比如通过音效提供反馈、通过环境音轨增加沉浸感、通过录制的语音讲述故事，或通过背景音乐传达各种情感。

自早期以来，视频游戏一直在利用声音。例如，1972 年的经典游戏《乒乓球》使用了蜂鸣音效来提供反馈，每当球与物体碰撞时，不同的音高用于区分与墙壁的碰撞、与球拍的碰撞或球离开游戏场地。

另一方面，《太空侵略者》通过逐渐加快歌曲的速度，巧妙地利用了其基本的背景音乐，随着外星人入侵的危险越来越近，从而增强了玩家内心的紧张感。研究表明，没有声音玩游戏的玩家没有感受到同样的紧迫感，他们的心率也没有像打开声音的玩家那样上升。

自那时以来，技术取得了许多进步，使得游戏中的音频得以显著发展。大多数游戏开始使用录制的音频而不是粗糙的合成音调，而新技术如 3D 音频现在允许玩家感觉到声音来自四面八方，并与游戏环境互动。

音乐在视频游戏中也扮演着非常重要的角色。流行的《最终幻想》游戏在情感上的巨大影响归功于植松伸夫创作的宏大、电影般的配乐。系列中最令人难忘的场景如果没有伴随着音乐，将不会是同样的。

许多开发者和作曲家也研究了使音乐与游戏玩法互动的方法。例如，从《猴岛小英雄 2：勒船长的复仇》开始，卢卡斯艺术公司创造的每个图形冒险游戏都使用了一种名为 iMUSE 的自定义交互式音乐系统，它允许主题之间的音乐过渡在玩家从一个房间移动到另一个房间时无缝进行。

甚至有一些游戏直接将音频概念融入到它们的主要游戏机制中，比如玩家必须记忆并在《塞尔达传说：时光之笛》中演奏的歌曲，以及完全围绕声音展开的游戏，最流行的例子是节奏游戏，比如《帕拉帕大冒险》、《舞力全开》或《吉他英雄》。

然而，尽管音频是视频游戏中如此重要的一部分，许多游戏开发书籍都只是粗略地涉及音频编程这个主题。即使是那些专门用一章来讲解音频的书籍，通常也只教授一些非常基础的知识，比如加载和播放音频文件，或者使用过时的音频引擎，而不是现在行业中使用的引擎。此外，其他游戏开发主题，如图形、物理或人工智能往往更吸引初级游戏开发者，学习音频变得不那么重要。

这本书的主要目标是通过使用一种流行且成熟的音频引擎，从几个不同的抽象级别涵盖音频编程，给你一个关于游戏音频编程的速成课程。我希望这种方法能够为你提供足够的知识，以实现大多数视频游戏通常需要的音频功能，并为你打下基础，使你能够追求更高级的主题。

# 这本书涵盖了什么

第一章，“音频概念”，涵盖了一些最重要的音频概念，如声波、模拟和数字音频、多声道音频和音频文件格式。

第二章，“音频播放”，展示了如何使用 FMOD 加载和播放音频文件，以及如何开始创建一个简单的音频管理器类。

第三章，“音频控制”，展示了如何控制声音的播放和参数，以及如何将声音分组到类别并同时控制它们。

第四章，“3D 音频”，涵盖了 3D 音频的最重要概念，比如定位音频、混响、遮挡/遮蔽，以及一些 DSP 效果。

第五章，“智能音频”，提供了使用 FMOD Designer 工具进行高级声音设计的概述，以及如何创建自适应和交互式声音事件和音乐的示例。

第六章，“低级音频”，提供了关于如何在非常低级别上处理音频的基本信息，通过直接操作和编写音频数据。

# 阅读本书所需的内容

阅读本书，您需要以下软件：

+   **C++ IDE**：提供了 Microsoft Visual Studio 的说明，但您也可以使用任何 C++ IDE 或编译器。Visual Studio 的 Express 版本是免费的，可以从微软网站下载。

+   **FMOD Ex**：第 2-4 章和第六章需要，可从[www.fmod.org](http://www.fmod.org)免费下载。

+   **FMOD Designer**：第五章需要。可从[www.fmod.org](http://www.fmod.org)免费下载。

+   **SFML**：网站上的所有代码示例也使用 SFML（2.0 版本）来处理其他任务，比如窗口管理、图形和输入处理。可从[www.sfml-dev.org](http://www.sfml-dev.org)免费下载。

# 本书的受众

本书面向具有少量或没有音频编程经验的 C++游戏开发人员，他们希望快速了解集成音频到游戏中所需的最重要主题。

您需要具备中级的 C++知识才能够理解本书中的代码示例，包括对基本的 C++标准库特性的理解，比如字符串、容器、迭代器和流。同时也建议具备一些游戏编程经验，但这不是必需的。

# 约定

在本书中，您会发现一些不同类型信息的文本样式。以下是一些样式的示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 账号显示如下：“注意函数通过参数返回`system`对象。”

代码块设置如下：

```cpp
#include <math.h>

float ChangeOctave(float frequency, float variation) {
  static float octave_ratio = 2.0f;
  return frequency * pow(octave_ratio, variation);
}
float ChangeSemitone(float frequency, float variation) {
  static float semitone_ratio = pow(2.0f, 1.0f / 12.0f);
  return frequency * pow(semitone_ratio, variation);
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```cpp
#include <SFML/Window.hpp>
#include "SimpleAudioManager.h"

int main() {
  sf::Window window(sf::VideoMode(320, 240), "AudioPlayback");
  sf::Clock clock;

  // Place your initialization logic here
 SimpleAudioManager audio;
 audio.Load("explosion.wav");

  // Start the game loop
  while (window.isOpen()) {
    // Only run approx 60 times per second
    float elapsed = clock.getElapsedTime().asSeconds();
    if (elapsed < 1.0f / 60.0f) continue;
    clock.restart();
    sf::Event event;
    while (window.pollEvent(event)) {
      // Handle window events
      if (event.type == sf::Event::Closed) 
        window.close();

      // Handle user input
      if (event.type == sf::Event::KeyPressed &&
          event.key.code == sf::Keyboard::Space)
 audio.Play("explosion.wav");
    }
    // Place your update and draw logic here
 audio.Update(elapsed);
  }
  // Place your shutdown logic here
  return 0;
}
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的方式出现在文本中：“对于接下来的所有步骤，请确保**配置**选项设置为**所有配置**。”

### 注意

警告或重要提示会以这样的方式出现。

### 提示

提示和技巧会以这种形式出现。


# 第一章：音频概念

如今，由于有许多强大的音频库可用，编写游戏的音频组件变得更加容易。这些库通过处理大部分底层实现细节来减轻开发人员的负担。虽然这是一件好事，但也使得更容易忽视理解声音理论的必要性。例如，我们可以轻松地播放一个声音文件，而不知道它在内存中的表示。

然而，即使在使用音频库时，仍然会有一些需要一些理论知识的情况。例如，我们经常会发现与理论相关的参数和函数名称，比如声音的频率或音频缓冲区的位深度。了解这些概念的含义对于确保我们正确使用它们是很重要的。

本章的目标是作为对我们在本书过程中最需要的概念的轻量级介绍。

# 声波

声音是由物体的振动产生的。这些振动产生大气压力的变化，以声波的形式传播离开物体。我们的耳朵能够检测到传入的声波，并将它们转换成我们的大脑解释为声音的神经信号。

可视化声音的一种方式是绘制每个时刻大气压力的变化图。然而，理解这些图与我们听到的声音之间的关系可能非常复杂。因此，我们通常从研究最简单的波形——**正弦波**开始。

正弦波对教育目的来说很有趣，因为我们可以从中轻松识别声音的两个主要属性：音量和音调。大多数音频库允许我们控制这些属性，以便我们播放任何声音。

+   **音量**：这个属性对应声音的响亮或安静程度。它直接取决于声波的振幅（或高度），如在垂直轴上测量的那样。音量的主要单位是分贝（dB），但大多数音频库使用从零（静音）到一（最大音量）的刻度。

+   **音调**：这个属性决定声音的高低。它取决于声波的频率，即它每秒重复的次数。频率的单位是赫兹（Hz）。关于频率，你应该知道的两件事是，人耳只能听到 20 赫兹到 20,000 赫兹范围内的频率，以及大多数你听到的声音实际上是几种不同频率的组合。

# 模拟和数字音频

现在我们知道了声音是什么，让我们把思绪转向录制声音并将其存储在计算机上。这个过程的第一步是将声波转换成电信号。当我们使用一个连续信号来表示另一种不同数量的信号时，我们称之为**模拟信号**，或者在声波的情况下，称之为**模拟音频信号**。你可能已经熟悉执行这种转换的设备：

+   **麦克风**：这些是将声波转换成电信号的设备

+   **扬声器**：这些是将电信号转换成声波的设备。

模拟信号有许多用途，但大多数计算机不能直接处理它们。计算机只能处理离散二进制数字序列，也称为**数字信号**。在计算机能够理解之前，我们需要将麦克风记录的模拟信号转换成数字信号，也就是数字音频。

用于数字表示模拟信号的最常用方法是**脉冲编码调制**（**PCM**）。 PCM 的一般思想是在固定时间间隔内对模拟信号的幅度进行采样（或测量），并将结果存储为一组数字（称为样本）。由于原始数据是连续的，而计算机上的数字是离散的，因此需要将样本四舍五入到最接近的可用数字，这个过程称为**量化**。样本通常存储为整数，但也可以使用浮点数，如以下示例所示：

![模拟和数字音频](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_01_03.jpg)

有两种方法可以控制采样音频的质量：

+   ** 采样率 **：也称为采样频率，它是每秒音频采取的样本数量。根据奈奎斯特采样定理，采样率应至少是模拟信号的最高频率的两倍，以便进行适当的重建。通常会使用 44,100 Hz 或 48,000 Hz 的值。以下图比较了不同速率的采样：![模拟和数字音频](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_01_04.jpg)

+   ** 位深度 **：也称为分辨率，它是用于表示单个样本的位数。这控制了每个样本可以取的可能离散值的数量，并且需要足够高以避免量化误差。通常会使用 16 位或 24 位的位深度，存储为整数，或者 32 位存储为浮点数。以下图比较了不同分辨率的采样：![模拟和数字音频](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_01_05.jpg)

# 多通道音频

我们应该谈论的另一个方面是许多音频系统具有多个输出。通过将不同的音频信号发送到单独的输出（称为通道），可以产生方向性和空间的错觉。这些系统上的通道数量可以从一个（**单声道**）或两个（**立体声**）到环绕声系统上的更多通道不等。

早些时候描述的 PCM 格式可以一次存储多个通道的音频，通过以正确顺序交错每个通道的一个样本。以下图显示了立体声系统的一个示例：

![多通道音频](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_01_06.jpg)

除了我们之前讨论过的音量和音调之外，还有另一个属性通常会在每个音频库中找到，称为**声像**。声像适用于立体声系统，并允许您模拟声音的位置，将其放置在左右声道之间的任何位置。对于具有两个以上通道的配置中的定位，通常会使用其他高级功能，例如 3D 声音。

# 音频文件格式

计算机上存储音频的文件格式有很多种，一开始可能会感到不知所措。幸运的是，大部分时间你只会在游戏中使用其中的一些。音频文件格式通常属于以下类别之一：

+   ** 未压缩音频文件 **：这些是音频文件，其中数据以其原始状态存储（通常为 PCM）。这意味着它们的数据已经准备好进行播放，无需进一步处理。缺点是它们在磁盘上占用大量空间（大约每分钟音频占用 10 MB）。例如，WAV 和 AIFF。

+   ** 无损压缩 **：这些是使用仅执行可逆更改的压缩算法对数据进行编码的音频文件，因此不会永久丢失任何信息。这些文件可以达到未压缩格式的一半大小，但需要计算机在播放之前对其进行解码。例如，FLAC 和 APE。

+   **有损压缩**：这些是音频文件，其中数据使用压缩算法进行编码，其中一些信息的丢失是可以接受的。这些算法使用启发式方法来确定数据的哪些部分不太可能被听到，以便丢弃它们。文件大小可以缩小到原始大小的 10％，尽管如果压缩过于强烈，声音质量可能会受到相当大的影响。例如，MP3，WMA 和 OGG。

+   **序列音乐**：有一些格式不适合前面提到的任何类别。例如，MIDI 文件只存储有关音乐应如何播放的信息，但不包含任何声音数据，将其留给计算机决定如何解释它们。因此，它们非常小，但声音质量有限，并且因系统而异。还有混合格式，如 MOD 文件（也称为模块或跟踪器文件），在许多方面类似于 MIDI 文件，但也包含播放它们所需的任何声音数据（称为乐器）。

请注意，尽管 MP3 很受欢迎，但它是一种受专利保护的格式，您不能在未支付版税的情况下进行商业使用（有关更多信息，请参阅[`mp3licensing.com/`](http://mp3licensing.com/)）。对于本书，我们将使用 OGG 文件进行长音效，使用 WAV 文件进行小音效。

# 总结

在本章中，我们看到声音是大气压力变化的一系列，以声波的形式传播。我们还看到声波具有振幅和频率等属性，控制着声音的响度和高度，并且您可以使用电信号（模拟音频）和一系列数字（数字音频）来表示声波。我们了解到，将模拟信号转换为数字信号时，需要控制采样率和位深度。最后，我们看到许多音频系统具有多个输出，并且有许多不同类型的音频文件格式。


# 第二章：音频播放

在本章中，我们将执行音频编程中最基本的两个操作——加载和播放音频文件。这可能看起来不像什么，但已经足够让我们开始将音频添加到我们的游戏中了。

如今有许多不同的音频库可用，如 DirectSound、Core Audio、PortAudio、OpenAL、FMOD 或 Wwise。有些仅在特定平台上可用，而其他一些几乎在任何地方都可以工作。有些是非常低级的，几乎只提供了用户和声卡驱动程序之间的桥梁，而其他一些则提供了高级功能，如 3D 音效或交互式音乐。

对于本书，我们将使用 FMOD，这是由 Firelight Technologies 开发的跨平台音频中间件，非常强大，但易于使用。然而，你应该更专注于所涵盖的概念，而不是 API，因为理解它们将使你更容易适应其他库，因为很多知识是可以互换的。

首先，我们将学习如何安装 FMOD，如何初始化和更新音频系统，以及如何让它播放音频文件。在本章结束时，我们将通过创建一个非常简单的音频管理器类来完成这些任务，它将所有这些任务封装在一个极简的接口后面。

# 理解 FMOD

我选择 FMOD 作为本书的主要原因之一是它包含两个单独的 API——FMOD Ex 程序员 API，用于低级音频播放，以及 FMOD Designer，用于高级数据驱动音频。这将使我们能够在不必使用完全不同的技术的情况下，以不同的抽象级别涵盖游戏音频编程。

### 提示

**下载示例代码**

你可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载你购买的所有 Packt 图书的示例代码文件。如果你在其他地方购买了这本书，你可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给你。

除此之外，FMOD 也是一款优秀的软件，对游戏开发者有几个优势：

+   **许可证**：它可以免费用于非商业用途，并且对于商业项目有合理的许可证。

+   **跨平台**：它可以在令人印象深刻的多个平台上运行。你可以在 Windows、Mac、Linux、Android、iOS 上运行它，并且在索尼、微软和任天堂的大多数现代游戏主机上也可以运行。

+   **支持的格式**：它原生支持大量的音频文件格式，这样就不用包含其他外部库和解码器了。

+   **编程语言**：你不仅可以使用 C 和 C++来使用 FMOD，还有其他编程语言的绑定可用，比如 C#和 Python。

+   **流行度**：它非常受欢迎，被广泛认为是目前的行业标准。它被用于游戏如 BioShock，Crysis，Diablo 3，Guitar Hero，Start Craft II 和 World of Warcraft。它还被用来驱动几个流行的游戏引擎，如 Unity3D 和 CryEngine。

+   **特点**：它功能齐全，涵盖了从简单的音频播放、流式传输和 3D 音效到交互式音乐、DSP 效果和低级音频编程的一切。

# 安装 FMOD Ex 程序员 API

首次安装 C++库可能有点令人生畏。好的一面是，一旦你第一次完成了这个过程，对于其他库来说，通常过程是一样的。如果你使用的是 Microsoft Visual Studio，你应该遂循以下步骤：

1.  从[`www.fmod.org`](http://www.fmod.org)下载 FMOD Ex 程序员 API 并将其安装到一个你可以记住的文件夹，比如`C:\FMOD`。

1.  创建一个新的空项目，并至少向其中添加一个`.cpp`文件。然后，在**解决方案资源管理器**上右键单击项目节点，并从列表中选择**属性**。对于接下来的所有步骤，请确保**配置**选项设置为**所有配置**。

1.  导航到**C/C++** | **常规**，并将`C:\FMOD\api\inc`添加到**附加包含目录**列表中（条目用分号分隔）。

1.  导航到**链接器** | **常规**，并将`C:\FMOD\api\lib`添加到**附加库目录**列表中。

1.  导航到**链接器** | **输入**，并将`fmodex_vc.lib`添加到**附加依赖项**列表中。

1.  导航到**生成事件** | **后期生成事件**，并将`xcopy /y "C:\FMOD\api\fmodex.dll" "$(OutDir)"`添加到**命令行**列表中。

1.  从您的代码中包含`<fmod.hpp>`头文件。

# 创建和管理音频系统

FMOD 内发生的一切都由一个名为`FMOD::System`的类管理，我们必须通过`FMOD::System`的`m_Create()`函数实例化它：

```cpp
FMOD::System* system;
FMOD::System_Create(&system);
```

请注意，该函数通过参数返回`system`对象。每当 FMOD 函数需要返回一个值时，您都会看到这种模式，因为它们都将常规返回值保留给错误代码。我们将在稍后讨论错误检查，但现在让我们让音频引擎运行起来。

现在我们已经实例化了一个`system`对象，我们还需要通过调用`init()`方法来初始化它：

```cpp
system->init(100, FMOD_INIT_NORMAL, 0);
```

第一个参数指定要分配的最大通道数。这控制了您能够同时播放多少个声音。您可以为此参数选择任何数字，因为系统在幕后执行一些聪明的优先级管理，并使用可用资源分配通道。第二个和第三个参数自定义了初始化过程，通常可以将它们保留为示例中所示。

我们将使用的许多功能只有在每帧更新`system`对象时才能正常工作。这是通过在游戏循环内调用`update()`方法来完成的：

```cpp
system->update();
```

您还应该记住在游戏结束之前关闭`system`对象，以便它可以处理所有资源。这是通过调用`release()`方法来完成的：

```cpp
system->release();
```

# 加载和流式传输音频文件

FMOD 最伟大的一点是，你可以用一个方法调用加载几乎任何音频文件格式。要将音频文件加载到内存中，请使用`createSound()`方法：

```cpp
FMOD::Sound* sound;
system->createSound("sfx.wav", FMOD_DEFAULT, 0, &sound);
```

要从磁盘流式传输音频文件而无需将其存储在内存中，请使用`createStream()`方法：

```cpp
FMOD::Sound* stream;
system->createStream("song.ogg", FMOD_DEFAULT, 0, &stream);
```

这两种方法都将音频文件的路径作为第一个参数，并通过第四个参数返回一个指向`FMOD::Sound`对象的指针，您可以使用它来播放声音。以前示例中的路径是相对于应用程序路径的。如果您在 Visual Studio 中运行这些示例，请确保将音频文件复制到输出文件夹中（例如，使用后期构建事件，如`xcopy /y "$(ProjectDir)*.ogg" "$(OutDir)"`）。

加载和流式传输之间的选择主要是内存和处理能力之间的权衡。当您加载音频文件时，所有数据都会被解压缩并存储在内存中，这可能会占用大量空间，但计算机可以轻松播放它。另一方面，流式传输几乎不使用任何内存，但计算机必须不断访问磁盘，并即时解码音频数据。另一个区别（至少在 FMOD 中）是，当您流式传输声音时，您一次只能播放一个实例。这种限制存在是因为每个流只有一个解码缓冲区。因此，对于必须同时播放多次的音效，您必须将它们加载到内存中，或者打开多个并发流。作为一个经验法则，流式传输非常适合音乐曲目、语音提示和环境曲目，而大多数音效应该加载到内存中。

第二个和第三个参数允许我们自定义声音的行为。有许多不同的选项可用，但以下列表总结了我们将要使用最多的选项。使用`FMOD_DEFAULT`等同于组合每个类别的第一个选项：

+   `FMOD_LOOP_OFF`和`FMOD_LOOP_NORMAL`：这些模式控制声音是否应该只播放一次，或者在达到结尾时循环播放

+   `FMOD_HARDWARE`和`FMOD_SOFTWARE`：这些模式控制声音是否应该在硬件中混合（性能更好）或软件中混合（更多功能）

+   `FMOD_2D`和`FMOD_3D`：这些模式控制是否使用 3D 声音

我们可以使用按位`OR`运算符组合多个模式（例如，`FMOD_DEFAULT | FMOD_LOOP_NORMAL | FMOD_SOFTWARE`）。我们还可以告诉系统在使用`createSound()`方法时流式传输声音，通过设置`FMOD_CREATESTREAM`标志。实际上，`createStream()`方法只是这样做的一个快捷方式。

当我们不再需要声音（或者游戏结束时），我们应该通过调用声音对象的`release()`方法来处理它。无论音频系统是否也被释放，我们都应该释放我们创建的声音。

```cpp
sound->release();
```

# 播放声音

将声音加载到内存中或准备好进行流式传输后，剩下的就是告诉系统使用`playSound()`方法来播放它们：

```cpp
FMOD::Channel* channel;
system->playSound(FMOD_CHANNEL_FREE, sound, false, &channel);
```

第一个参数选择声音将在哪个通道播放。通常应该让 FMOD 自动处理，通过将`FMOD_CHANNEL_FREE`作为参数传递。

第二个参数是指向要播放的`FMOD::Sound`对象的指针。

第三个参数控制声音是否应该在暂停状态下开始，让您有机会修改一些属性，而这些更改不会被听到。如果您将其设置为 true，您还需要使用下一个参数，以便稍后取消暂停。

第四个参数是一个输出参数，返回`FMOD::Channel`对象的指针，声音将在其中播放。您可以使用此句柄以多种方式控制声音，这将是下一章的主要内容。

如果您不需要对声音进行任何控制，可以忽略最后一个参数，并在其位置传递`0`。这对于非循环的一次性声音很有用。

```cpp
system->playSound(FMOD_CHANNEL_FREE, sound, false, 0);
```

# 检查错误

到目前为止，我们假设每个操作都会顺利进行，没有错误。然而，在实际情况下，有很多事情可能会出错。例如，我们可能会尝试加载一个不存在的音频文件。

为了报告错误，FMOD 中的每个函数和方法都有一个`FMOD_RESULT`类型的返回值，只有当一切顺利时才会等于`FMOD_OK`。用户需要检查这个值并做出相应的反应：

```cpp
FMOD_RESULT result = system->init(100, FMOD_INIT_NORMAL, 0);
if (result != FMOD_OK) {
  // There was an error, do something about it
}
```

首先，了解错误是什么将是有用的。然而，由于`FMOD_RESULT`是一个枚举，如果尝试打印它，您只会看到一个数字。幸运的是，在`fmod_errors.h`头文件中有一个名为`FMOD_ErrorString()`的函数，它将为您提供完整的错误描述。

您可能还想创建一个辅助函数来简化错误检查过程。例如，以下函数将检查错误，将错误描述打印到标准输出，并退出应用程序：

```cpp
#include <iostream>
#include <fmod_errors.h>

void ExitOnError(FMOD_RESULT result) {
  if (result != FMOD_OK) {
    std::cout << FMOD_ErrorString(result) << std::endl;
    exit(-1);
  }
}
```

然后，您可以使用该函数来检查是否有任何应该导致应用程序中止的关键错误：

```cpp
ExitOnError(system->init(100, FMOD_INIT_NORMAL, 0));
```

前面描述的初始化过程也假设一切都会按计划进行，但真正的游戏应该准备好处理任何错误。幸运的是，FMOD 文档中提供了一个模板，向您展示如何编写健壮的初始化序列。这里涵盖的内容有点长，所以我建议您参考文档文件夹中名为`Getting started with FMOD for Windows.pdf`的文件，以获取更多信息。

为了清晰起见，所有的代码示例将继续在没有错误检查的情况下呈现，但在实际项目中，你应该始终检查错误。

# 项目 1 - 构建一个简单的音频管理器

在这个项目中，我们将创建一个`SimpleAudioManager`类，它结合了本章涵盖的所有内容。创建一个仅公开我们需要的操作的底层系统的包装器被称为**外观设计模式**，在保持事情简单的同时非常有用。

由于我们还没有看到如何操作声音，不要指望这个类足够强大，可以用于复杂的游戏。它的主要目的将是让你用非常少的代码加载和播放一次性音效（实际上对于非常简单的游戏可能已经足够了）。

它还会让你摆脱直接处理声音对象（并且需要释放它们）的责任，通过允许你通过文件名引用任何加载的声音。以下是如何使用该类的示例：

```cpp
SimpleAudioManager audio;
audio.Load("explosion.wav");
audio.Play("explosion.wav");
```

从教育角度来看，也许更重要的是，你可以将这个练习作为一种获取一些关于如何调整技术以满足你需求的想法的方式。它还将成为本书后续章节的基础，我们将构建更复杂的系统。

## 类定义

让我们从检查类定义开始：

```cpp
#include <string>
#include <map>
#include <fmod.hpp>

typedef std::map<std::string, FMOD::Sound*> SoundMap;

class SimpleAudioManager {
 public:
  SimpleAudioManager();
  ~SimpleAudioManager();
  void Update(float elapsed);
  void Load(const std::string& path);
  void Stream(const std::string& path);
  void Play(const std::string& path);
 private:
  void LoadOrStream(const std::string& path, bool stream);
  FMOD::System* system;
  SoundMap sounds;
};
```

通过浏览公共类成员列表，应该很容易推断它能做什么：

+   该类可以使用`Load()`方法加载音频文件（给定路径）

+   该类可以使用`Stream()`方法流式传输音频文件（给定路径）

+   该类可以使用`Play()`方法播放音频文件（前提是它们已经被加载或流式传输）

+   还有一个`Update()`方法和一个构造函数/析构函数对来管理声音系统

另一方面，私有类成员可以告诉我们很多关于类内部工作的信息：

+   该类的核心是一个`FMOD::System`实例，负责驱动整个声音引擎。该类在构造函数中初始化声音系统，并在析构函数中释放它。

+   声音存储在一个关联容器中，这允许我们根据文件路径搜索声音。为此，我们将依赖于 C++标准模板库（STL）关联容器之一，`std::map`类，以及用于存储键的`std::string`类。查找字符串键有点低效（例如与整数相比），但对于我们的需求来说应该足够快。将所有声音存储在单个容器中的优势是我们可以轻松地遍历它们并从类析构函数中释放它们。

+   由于加载和流式传输音频文件的代码几乎相同，公共功能已经被提取到一个名为`LoadOrStream()`的私有方法中，`Load()`和`Stream()`将所有工作委托给它。这样可以避免不必要地重复代码。

## 初始化和销毁

现在，让我们逐一实现每个方法。首先是类构造函数，非常简单，因为它唯一需要做的就是初始化`system`对象。

```cpp
SimpleAudioManager::SimpleAudioManager() {
  FMOD::System_Create(&system);
  system->init(100, FMOD_INIT_NORMAL, 0);
}
```

更新更简单，只需要一个方法调用：

```cpp
void SimpleAudioManager::Update(float elapsed) {
  system->update();
}
```

另一方面，析构函数需要负责释放`system`对象，以及创建的所有声音对象。不过，这个过程并不复杂。首先，我们遍历声音的映射，依次释放每一个，并在最后清除映射。如果你以前从未使用过 STL 迭代器，语法可能会显得有点奇怪，但它的意思只是从容器的开头开始，不断前进直到达到末尾。然后我们像往常一样释放`system`对象。

```cpp
SimpleAudioManager::~SimpleAudioManager() {
  // Release every sound object and clear the map
  SoundMap::iterator iter;
  for (iter = sounds.begin(); iter != sounds.end(); ++iter)
    iter->second->release();
  sounds.clear();

  // Release the system object
  system->release();
  system = 0;
}
```

## 加载或流式传输声音

接下来是`Load()`和`Stream()`方法，但让我们先来看一下私有的`LoadOrStream()`方法。这个方法以音频文件的路径作为参数，并检查它是否已经被加载（通过查询声音映射）。如果声音已经被加载，就没有必要再次加载，所以该方法返回。否则，文件将被加载（或流式传输，取决于第二个参数的值），并存储在声音映射中的适当键下。

```cpp
void SimpleAudioManager::LoadOrStream(const std::string& path, bool stream) {
  // Ignore call if sound is already loaded
  if (sounds.find(path) != sounds.end()) return;

  // Load (or stream) file into a sound object
  FMOD::Sound* sound;
  if (stream)
    system->createStream(path.c_str(), FMOD_DEFAULT, 0, &sound);
  else
    system->createSound(path.c_str(), FMOD_DEFAULT, 0, &sound);

  // Store the sound object in the map using the path as key
  sounds.insert(std::make_pair(path, sound));
}
```

有了前面的方法，`Load()`和`Stream()`方法可以轻松实现如下：

```cpp
void SimpleAudioManager::Load(const std::string& path) {
  LoadOrStream(path, false);
}
void SimpleAudioManager::Stream(const std::string& path) {
  LoadOrStream(path, true);
}
```

## 播放声音

最后，还有`Play()`方法，它的工作方式相反。它首先检查声音是否已经加载，如果在地图上找不到声音，则不执行任何操作。否则，使用默认参数播放声音。

```cpp
void SimpleAudioManager::Play(const std::string& path) {
  // Search for a matching sound in the map
  SoundMap::iterator sound = sounds.find(path);

  // Ignore call if no sound was found
  if (sound == sounds.end()) return;

  // Otherwise play the sound
  system->playSound(FMOD_CHANNEL_FREE, sound->second, false, 0);
}
```

我们本可以尝试在找不到声音时自动加载声音。一般来说，这不是一个好主意，因为加载声音是一个昂贵的操作，我们不希望在关键的游戏过程中发生这种情况，因为这可能会减慢游戏速度。相反，我们应该坚持分开加载和播放操作。

## 关于代码示例的说明

尽管这是一本关于音频的书，但所有示例都需要一个运行环境。为了尽可能清晰地保持示例的音频部分，我们还将使用**Simple and Fast Multimedia Library 2.0**（SFML）（[`www.sfml-dev.org`](http://www.sfml-dev.org)）。这个库可以非常容易地处理所有杂项任务，比如窗口创建、定时、图形和用户输入，这些任务在任何游戏中都会找到。

例如，这里有一个使用 SFML 和`SimpleAudioManager`类的完整示例。它创建一个新窗口，加载一个声音，以 60 帧每秒的速度运行游戏循环，并在用户按下空格键时播放声音。

```cpp
#include <SFML/Window.hpp>
#include "SimpleAudioManager.h"

int main() {
  sf::Window window(sf::VideoMode(320, 240), "AudioPlayback");
  sf::Clock clock;

  // Place your initialization logic here
 SimpleAudioManager audio;
 audio.Load("explosion.wav");

  // Start the game loop
  while (window.isOpen()) {
    // Only run approx 60 times per second
    float elapsed = clock.getElapsedTime().asSeconds();
    if (elapsed < 1.0f / 60.0f) continue;
    clock.restart();
    sf::Event event;
    while (window.pollEvent(event)) {
      // Handle window events
      if (event.type == sf::Event::Closed) 
        window.close();

      // Handle user input
      if (event.type == sf::Event::KeyPressed &&
          event.key.code == sf::Keyboard::Space)
 audio.Play("explosion.wav");
    }
    // Place your update and draw logic here
 audio.Update(elapsed);
  }
  // Place your shutdown logic here
  return 0;
}
```

# 总结

在本章中，我们已经看到了使用 FMOD 音频引擎的一些优势。我们看到了如何在 Visual Studio 中安装 FMOD Ex 程序员 API，如何初始化、管理和释放 FMOD 音频系统，如何从磁盘加载或流式传输任何类型的音频文件，如何播放先前由 FMOD 加载的声音，如何检查每个 FMOD 函数中的错误，以及如何创建一个简单的音频管理器，它封装了加载和播放音频文件的操作背后的简单接口。


# 第三章：音频控制

在上一章中，我们看到了如何在 FMOD 中加载和播放音频文件。这一次，我们将探讨一些控制这些文件播放的方式。我们将从控制播放流程开始，通过按需停止声音或寻找音频文件中的不同点。然后，我们将介绍如何修改声音的主要属性，这些属性在第一章“音频概念”中已经描述，例如音量和音调。我们还将看到 FMOD 如何让我们将声音分组到类别中，以便一次控制多个声音。

在本章末尾，我们将扩展上一章的音频管理器，并使其更加灵活和适合在游戏中使用。这个扩展的音频管理器将区分歌曲和音效，并分别处理它们。我们将看到如何使用简单的音量调节来实现淡入/淡出效果，以及如何通过一点随机性为音效添加变化。音频管理器还将为每个类别公开单独的音量控制，使其易于从游戏的选项屏幕进行控制。

# 通道句柄

让我们从上一章快速回顾一下。当我们使用`playSound()`方法并将`FMOD::Channel`指针的地址传递给第四个参数时，我们会得到一个通道句柄作为返回：

```cpp
FMOD::Channel* channel;
system->playSound(FMOD_CHANNEL_FREE, sound, false, &channel);
```

通过这个句柄，我们可以以许多方式控制声音。只要声音尚未播放完毕，或者直到我们明确停止声音为止，该句柄仍然有效。如果我们尝试在声音停止后对通道执行操作，什么也不会发生。相反，我们调用的方法会返回一个错误，说明通道句柄无效，或者已经被另一个声音使用，如果是这种情况的话。

可能令人困惑的是，这个 FMOD 通道与我们在第一章“音频概念”中讨论的多通道音频不是同一类型。这只是 FMOD 为同时播放声音使用的每个插槽的名称。

# 控制播放

我们已经知道如何播放音频文件，但重要的是要知道如何停止它们的播放。这对于循环声音尤为重要，否则它们将永远重复。通常，我们只需要在通道句柄上调用`stop()`方法：

```cpp
channel->stop();
```

当声音停止播放时——因为它已经到达结尾并且没有设置循环，或者因为我们自己停止了它——它的通道就变得空闲，供其他声音使用。这意味着一旦我们停止了声音，就没有办法恢复它。如果我们需要暂时停止声音，并在以后恢复它，我们需要使用`setPaused()`方法：

```cpp
// Pause the sound
channel->setPaused(true);
// Resume the sound
channel->setPaused(false);
```

大多数以`set`开头的方法都有相应的`get`方法，例如`getPaused()`，我们可以使用它来检查该属性的当前值。以下是一个使用这两种方法结合在一起的函数，用于切换通道的暂停状态：

```cpp
void TogglePaused(FMOD::Channel* channel) {
  bool paused;
  channel->getPaused(&paused);
  channel->setPaused(!paused);
}
```

另一个常见的操作是将声音定位到文件中的不同位置。这是通过`setPosition()`方法完成的，该方法接受一个数字，表示我们要寻找的位置，以及我们指定该位置的单位（在以下示例中为毫秒）。如果我们想要使声音在暂停后从头开始播放，这将非常有用：

```cpp
channel->setPosition(0, FMOD_TIMEUNIT_MS);
```

最后，如果我们有一个循环声音，我们可以使用`setLoopCount()`方法来控制声音循环的次数。以下示例显示了一些可能的参数（默认值为`-1`表示无限循环）：

```cpp
// Repeat endlessly
channel->setLoopCount(-1);
// Play once then, stop
channel->setLoopCount(0);
// Play three times, then stop
channel->setLoopCount(2);
```

# 控制音量

接下来，我们将看到如何控制声音的一些主要属性，首先是音量。这是通过简单调用`setVolume()`方法完成的，该方法接受一个值，范围从`0`（静音）到`1`（最大音量）：

```cpp
channel->setVolume(1.0f);
```

与我们之前暂停声音的方式类似，我们也可以使用`setMute()`方法暂时将其静音。一旦我们取消静音，声音就会以先前的音量继续播放：

```cpp
channel->setMute(true);
```

前面提到的两种方法都同时修改声音的所有通道。对于具有多个通道的声音，我们可以使用`setInputChannelMix()`方法分别修改每个通道的音量。通过将音量级别的数组作为第一个参数，通道数作为第二个参数，可以对任意数量的通道进行操作。以下是一个静音左声道的立体声声音的示例：

```cpp
float levels[2] = {0.0f, 1.0f};
channel->setInputChannelMix(levels, 2);
```

# 声像的控制

控制音调并不像控制音量那样直接。我们已经知道修改声音的频率会改变它的音调，通道句柄实际上有一个专门用于此目的的`setFrequency()`方法。

```cpp
channel->setFrequency(261.626f);
```

然而，它的工作方式并不是我们一些人可能期望的。例如，钢琴上的中央 C 音符的频率大约为 261.626 赫兹，因此我们可能期望将频率设置为该值会使声音产生接近中央 C 音符的音调，但事实并非如此。

为了理解这个问题，让我们首先关注`getFrequency()`方法。如果我们在具有其原始频率的通道上调用此方法，我们实际上得到的是声音的采样率。这意味着我们设置的任何频率值必须相对于这个值，换句话说，任何高于声音的原始采样率的值都会增加其音调，反之亦然。

我们可以任意选择频率值来获得所需的效果，但处理音调的更简单方法是用音乐术语。在音乐理论中，两个音高之间的差异称为音程，其中最基本的两种音程是八度，对应于具有相同名称的两个连续音符之间的距离，以及半音，对应于任何两个相邻音符之间的距离。以下是一些简单的规则；我们可以通过任何这些音程来修改现有的频率：

+   每当我们将频率乘以/除以两，我们得到一个听起来音调更高/更低的新频率

+   每当我们将频率乘以/除以两个半，我们得到一个听起来音调更高/更低的新频率

为了简化问题，这里有两个辅助方法，可以在给定频率和要更改的八度或半音数的情况下执行先前的计算。请注意使用`pow()`函数来应用先前的乘法和除法所需的次数：

```cpp
#include <math.h>

float ChangeOctave(float frequency, float variation) {
  static float octave_ratio = 2.0f;
  return frequency * pow(octave_ratio, variation);
}
float ChangeSemitone(float frequency, float variation) {
  static float semitone_ratio = pow(2.0f, 1.0f / 12.0f);
  return frequency * pow(semitone_ratio, variation);
}
```

使用这些辅助方法，可以简单地在 FMOD 中有意义地修改声音的音调。例如，要将声音的音调降低 3 个半音，我们可以这样做：

```cpp
float frequency;
channel->getFrequency(&frequency);
float newFrequency = ChangeSemitone(frequency, -3.0f);
channel->setFrequency(newFrequency);
```

请注意，改变声音的频率也会导致加快或减慢速度的副作用。有一种方法可以在 FMOD 中改变声音的音调而不影响其速度，但这需要使用 DSP 效果，这超出了本章的范围。我们将在下一章简要介绍 DSP 效果。

# 声像的控制

最后，只要声音是单声道或立体声，并且是 2D 的（因为 FMOD 引擎会自动定位 3D 声音），我们还可以控制一些声音的声像。当满足这些条件时，可以使用`setPan()`方法来改变声音的声像，该方法接受从`-1`（完全在左边）到`1`（完全在右边）的任何值。

```cpp
channel->setPan(-1.0f);
```

声像通过修改每个输出的音量来产生位置的错觉。然而，FMOD 计算这些值的方式在单声道和立体声声音之间是不同的。

对于单声道声音，每个扬声器的音量遵循一个恒定的功率曲线，从一侧的 0％开始，到另一侧的 100％，中心位置在大约 71％左右。这种技术使得从一侧到另一侧的过渡比使用中间 50％的常规线性插值更加平滑（因为我们感知声音强度的方式）。

另一方面，立体声声音使用一个更简单的公式，称为设置声音的平衡。使用这种方法，两个输出在中心位置已经达到 100％，向一侧平移只会以线性方式减小相反通道的音量。以下图示了这两种方法：

![控制声像定位](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_03_01.jpg)

# 将通道组分组在一起

FMOD 的另一个很棒的功能是它让我们将不同的通道添加到一个组中并同时控制它们。这对于视频游戏非常有用，因为声音往往属于不同的类别（如背景音乐、音效或语音）。要创建一个通道组，我们使用系统对象的`createChannelGroup()`方法：

```cpp
FMOD::ChannelGroup* musicGroup;
system->createChannelGroup("music", &musicGroup);
```

然后，我们可以使用通道对象的`setChannelGroup()`方法轻松地将通道添加到组中：

```cpp
channel->setChannelGroup(musicGroup);
```

还可以将一个组作为另一个组的子级添加，从而创建一个层次结构。这是使用父通道组对象的`addGroup()`方法完成的：

```cpp
channelGroup->addGroup(anotherGroup);
```

还有一个名为主通道组的全局通道组，在播放声音时每次都会将每个通道放置在其中。您可以通过调用系统对象的`getMasterChannelGroup()`方法来获取主通道组的引用：

```cpp
FMOD::ChannelGroup* masterGroup;
system->getMasterChannelGroup(&masterGroup);
```

在游戏中组织声音的一个好方法是为每个声音类别创建一个通道组，并将所有通道组添加到主通道组中。这样我们既可以控制各个类别，又可以一次性控制所有声音。

# 控制通道组

通道组支持的大多数操作与我们已经看到的个别通道相同。特别是，我们可以停止、暂停或静音组中的所有通道，并控制它们的音量和音调。这些操作的语法与以前相同，除了音调，它是通过`setPitch()`方法完成的，该方法不是频率，而是取`0`到`10`之间的任何值，并将其乘以当前频率。

```cpp
// Calls stop on all channels in the group
channelGroup->stop();
// Mute or pause all channels
channelGroup->setMute(true);
channelGroup->setPaused(true);
// Halve the volume of all sounds in the group
channelGroup->setVolume(0.5f);
// Double the frequency of all sounds in the group
channelGroup->setPitch(2.0f);
```

所有这些更改会自动传播到通道组层次结构中，而不会覆盖通道中存储的值。这些值的应用方式取决于操作的类型。

对于暂停和静音等操作，通道组中的值会覆盖子通道中的值。这意味着如果通道组被暂停，每个通道都将保持暂停，而不考虑它们的实际值。另一方面，如果通道组没有暂停，通道中的个别值将被考虑。

对于音量和音调，通道组中的值会乘以子通道中的值。例如，在 50％音量的通道组中的 80％音量的通道将以 40％的音量播放。

# 项目 2-改进音频管理器

在这个项目中，我们将在上一章中开发的简单音频管理器的基础上进行改进，使其更加灵活和游戏导向。这一次，除了加载和播放声音，我们还将能够停止它们并控制它们的音量，这在几乎每个游戏中都是必要的。此外，我们将所有声音分为两类，每类都有自己的特性和行为：

+   **音效（SFXs）**：加载到内存中并且不循环的声音。可以同时播放多个实例。它们的音量和音调可以直接控制，或者在用户定义的范围内进行随机化，以增加声音的变化。

+   **歌曲**：流式传输的声音，设置为循环。一次只能播放一首歌曲。音频管理器通过音量淡入淡出平稳处理歌曲之间的过渡。

每个游戏都有自己的需求，因此您可能希望创建更多类别，比如针对语音或环境音轨的类别。

## 类定义

让我们再次从类定义的列表开始：

```cpp
#include <string>
#include <map>
#include <fmod.hpp>

class AudioManager {
 public:
  AudioManager();
  ~AudioManager();
  void Update(float elapsed);

  void LoadSFX(const std::string& path);
  void LoadSong(const std::string& path);

  void PlaySFX(const std::string& path, 
               float minVolume, float maxVolume,
               float minPitch, float maxPitch);
  void PlaySong(const std::string& path);

  void StopSFXs();
  void StopSongs();

  void SetMasterVolume(float volume);
  void SetSFXsVolume(float volume);
  void SetSongsVolume(float volume);

 private:
  typedef std::map<std::string, FMOD::Sound*> SoundMap;
  enum Category { CATEGORY_SFX, CATEGORY_SONG, CATEGORY_COUNT };

  void Load(Category type, const std::string& path);

  FMOD::System* system;
  FMOD::ChannelGroup* master;
  FMOD::ChannelGroup* groups[CATEGORY_COUNT];
  SoundMap sounds[CATEGORY_COUNT];
  FMOD_MODE modes[CATEGORY_COUNT];

  FMOD::Channel* currentSong;
  std::string currentSongPath;
  std::string nextSongPath;

  enum FadeState { FADE_NONE,  FADE_IN, FADE_OUT };
  FadeState fade;
};
```

该类包含的成员比`SimpleAudioManager`类多得多，但基础是相同的。总结一下不同之处，现在我们有了用于分别加载、播放、停止和控制音效和歌曲音量的公共方法。然后，在类的私有部分，我们有一个包含类别类型的枚举，以及通道组、声音映射和模式的数组，每个类别都有足够的条目。最后，还有一些变量用于处理歌曲之间的过渡。

## 初始化和销毁

在构造函数中，除了初始化声音系统外，我们为每个声音类别创建了一个组通道，并将它们添加到主通道组中。我们还初始化了一个描述每个类别中的声音应如何加载的模式数组。最后，我们初始化了用于播放音效的随机数生成器。

```cpp
AudioManager::AudioManager() : currentSong(0), fade(FADE_NONE) {
  // Initialize system
  FMOD::System_Create(&system);
  system->init(100, FMOD_INIT_NORMAL, 0);

 // Create channels groups for each category
 system->getMasterChannelGroup(&master);
 for(int i = 0; i < CATEGORY_COUNT; ++i) {
 system->createChannelGroup(0, &groups[i]);
 master->addGroup(groups[i]);
 }

 // Set up modes for each category
 modes[CATEGORY_SFX] = FMOD_DEFAULT;
 modes[CATEGORY_SONG] = FMOD_DEFAULT | FMOD_CREATESTREAM |
 FMOD_LOOP_NORMAL;

 // Seed random number generator for SFXs
 srand(time(0));
}
```

在析构函数中，我们做了与简单音频管理器中相同的事情，但这次有多个声音映射需要清除。

```cpp
AudioManager::~AudioManager() {
  // Release sounds in each category
  SoundMap::iterator iter;
 for(int i = 0; i < CATEGORY_COUNT; ++i) {
    for (iter = sounds[i].begin(); iter != sounds[i].end(); ++iter)
      iter->second->release();
    sounds[i].clear();
  }
  // Release system
  system->release();
}
```

## 加载歌曲和音效

管理器的加载部分与上一章所做的非常相似。公共方法“LoadSFX（）”和“LoadSong（）”将它们的工作委托给私有的“Load（）”方法，该方法执行实际的加载过程。唯一的区别是，“Load（）”方法需要根据第一个参数的值使用正确的声音映射和模式数组：

```cpp
void AudioManager::LoadSFX(const std::string& path) {
  Load(CATEGORY_SFX, path);
}
void AudioManager::LoadSong(const std::string& path) {
  Load(CATEGORY_SONG, path);
}
void AudioManager::Load(Category type, const std::string& path) {
  if (sounds[type].find(path) != sounds[type].end()) return;
  FMOD::Sound* sound;
  system->createSound(path.c_str(), modes[type], 0, &sound);
  sounds[type].insert(std::make_pair(path, sound));
}
```

## 播放和停止音效

音效是两种类别中较容易播放的。 “PlaySFX（）”方法接受声音的路径和一对最小和最大音量和音调值。然后它在正确的映射中搜索声音，并像以前一样播放它，只是它使用在选定范围内生成的随机值来设置声音的音量和音调：

```cpp
void AudioManager::PlaySFX(const std::string& path,
                           float minVolume, float maxVolume,
                           float minPitch, float maxPitch) {
  // Try to find sound effect and return if not found
  SoundMap::iterator sound = sounds[CATEGORY_SFX].find(path);
  if (sound == sounds[CATEGORY_SFX].end()) return;

  // Calculate random volume and pitch in selected range
  float volume = RandomBetween(minVolume, maxVolume);
  float pitch = RandomBetween(minPitch, maxPitch);

  // Play the sound effect with these initial values
  FMOD::Channel* channel;
  system->playSound(FMOD_CHANNEL_FREE, sound->second,
                    true, &channel);
  channel->setChannelGroup(groups[CATEGORY_SFX]);
  channel->setVolume(volume);
  float frequency;
  channel->getFrequency(&frequency);
  channel->setFrequency(ChangeSemitone(frequency, pitch));
  channel->setPaused(false);
}
```

上述代码使用了两个辅助方法，“ChangeSemitone（）”在本章前面已经展示过，而“RandomBetween（）”可以在以下代码片段中看到：

```cpp
#include <stdlib.h>
#include <time.h>

float RandomBetween(float min, float max) {
  if(min == max) return min;
  float n = (float)rand()/(float)RAND_MAX;
  return min + n * (max - min);
}
```

停止播放所有音效非常容易实现，这要归功于通道组。通常在切换场景或打开菜单时调用此方法：

```cpp
void AudioManager::StopSFXs() {
  groups[CATEGORY_SFX]->stop();
}
```

## 播放和停止歌曲

由于我们只希望一次只播放一首歌曲，并且希望它们之间的过渡能够平稳进行，所以歌曲的处理会有些困难。FMOD 没有提供自动在声音之间淡入淡出的方法，因此我们必须在“Update（）”方法中手动实现这一点，使用“setVolume（）”调用。首先，我们需要创建一些成员变量来存储一些状态：

```cpp
FMOD::Channel* currentSong;
std::string currentSongPath;
std::string nextSongPath;
enum FadeState { FADE_NONE,  FADE_IN, FADE_OUT };
FadeState fade;
```

从顶部开始，我们需要通道句柄来更新歌曲的音量，当前歌曲的路径以确保我们不再次播放相同的歌曲，以及下一首歌曲的路径，以便在前一首歌曲淡出后开始播放。我们还需要一个变量来存储我们当前是在淡入还是淡出。 “PlaySong（）”方法遵循这些规则：

+   如果我们试图播放已经在播放的歌曲，则不应该发生任何事情。

+   如果我们试图播放一首歌曲，但已经有另一首歌曲在播放，我们不能立即开始。相反，我们指示管理器开始停止当前的歌曲，并存储要在之后播放的歌曲的路径。

+   如果没有歌曲正在播放，我们可以立即开始新的歌曲，其初始音量设置为零，并将管理器设置为淡入状态。歌曲还必须添加到正确的通道组中：

```cpp
void AudioManager::PlaySong(const std::string& path) {
  // Ignore if this song is already playing
  if(currentSongPath == path) return;

  // If a song is playing stop them and set this as the next song
  if(currentSong != 0) {
    StopSongs();
    nextSongPath = path;
    return;
  }
  // Find the song in the corresponding sound map
  SoundMap::iterator sound = sounds[CATEGORY_SONG].find(path);
  if (sound == sounds[CATEGORY_SONG].end()) return;

  // Start playing song with volume set to 0 and fade in
  currentSongPath = path;
  system->playSound(FMOD_CHANNEL_FREE, 
                    sound->second, true, &currentSong);
  currentSong->setChannelGroup(groups[CATEGORY_SONG]);
  currentSong->setVolume(0.0f);
  currentSong->setPaused(false);
  fade = FADE_IN;
}
```

+   `StopSongs()` 方法实现起来要简单得多，因为它只需要在歌曲正在播放时触发淡出，并清除先前设置的任何待定歌曲请求：

```cpp
void AudioManager::StopSongs() {
  if(currentSong != 0) 
    fade = FADE_OUT;
  nextSongPath.clear();
}
```

在 `Update()` 方法中，所有的淡入淡出都是在这里进行的。这个过程遵循以下规则：

+   如果有歌曲正在播放并且我们正在淡入，就稍微增加当前歌曲的音量。一旦音量达到一，就停止淡入。

+   如果有歌曲正在播放并且我们正在淡出，就稍微降低当前歌曲的音量。一旦音量达到零，就停止歌曲播放，并停止淡出。

+   如果没有歌曲正在播放，并且设置了下一首歌曲要播放，就开始播放它：

```cpp
void AudioManager::Update(float elapsed) {
  const float fadeTime = 1.0f; // in seconds
  if(currentSong != 0 && fade == FADE_IN) {
    float volume;
    currentSong->getVolume(&volume);
    float nextVolume = volume + elapsed / fadeTime;
    if(nextVolume >= 1.0f) {
      currentSong->setVolume(1.0f);
      fade = FADE_NONE;
    } else {
      currentSong->setVolume(nextVolume);
    }
  } else if(currentSong != 0 && fade == FADE_OUT) {
    float volume;
    currentSong->getVolume(&volume);
    float nextVolume = volume - elapsed / fadeTime;
    if(nextVolume <= 0.0f) {
      currentSong->stop();
      currentSong = 0;
      currentSongPath.clear();
      fade = FADE_NONE;
    } else {
      currentSong->setVolume(nextVolume);
    }
  } else if(currentSong == 0 && !nextSongPath.empty()) {
    PlaySong(nextSongPath);
    nextSongPath.clear();
  }
  system->update();
}
```

## 控制每个类别的主音量

控制每个类别的主音量只是调用相应的通道组方法的问题：

```cpp
void AudioManager::SetMasterVolume(float volume) {
  master->setVolume(volume);
}
void AudioManager::SetSFXsVolume(float volume) {
  groups[CATEGORY_SFX]->setVolume(volume);
}
void AudioManager::SetSongsVolume(float volume) {
  groups[CATEGORY_SONG]->setVolume(volume);
}
```

# 总结

在本章中，我们已经看到了如何控制声音的播放，如何控制声音的音量、音调和声像，如何使用通道组同时控制多个声音，最后如何将这些特性应用到实际情况中，比如在歌曲之间淡入淡出，或者对声音效果应用随机变化。


# 第四章：3D 音频

我们对声音的感知取决于我们相对于其来源的位置以及环境的几个特征。我们已经讨论过声音是一种机械波，它有一个起源，并且需要在我们听到它之前一直传播到我们的耳朵。在传播过程中，这些声波与环境（如墙壁、物体或空气本身）相互作用，并开始改变。许多这些变化为我们的大脑提供了有价值的线索，以确定声音的位置或环境的性质。以下是一些对声音产生重要影响的因素的列表：

+   **距离**：声音源和我们的耳朵之间的距离对其强度有显著影响，因为空气和其他介质会在声音经过时减弱声音。

+   **方向**：由于每只耳朵捕捉到的声音之间的微小时间和强度变化，我们的耳朵可以确定声音来自的方向。

+   **运动**：声源和我们的耳朵之间的相对速度可能会使其听起来具有不同的音调，这是由于一种称为多普勒效应的现象。

+   **房间**：我们所处的房间的大小和形状可能会导致多重回声积累，产生混响效果，声音似乎在原始声音停止后仍然暂时存在。

+   **障碍物**：声源和我们的耳朵之间的障碍物倾向于减弱和消音声音。这在大型障碍物（如墙壁）的情况下尤为明显。

在本章中，我们将探讨 3D 音频的基础知识，这是音频编程领域试图考虑这些因素中的一些（或全部）以产生逼真音频模拟的领域。这是使用 FMOD 等音频引擎的领域之一，因为要自己实现这些功能将会非常困难。

# 定位音频

我们要处理的 3D 音频的第一个方面（也许是最重要的）是定位音频。**定位音频**主要涉及产生声音的每个对象（我们将其称为**音频源**）相对于我们的耳朵（我们将其称为**音频听者**）的位置。

创建 3D 音频模拟所需的第一步是描述环境中的每个音频源和听者。请注意，场景中通常只有一个音频听者，除非我们正在创建多人分屏类型的游戏。以下图显示了一个场景的示例，其中有多个音频源和一个音频听者在中间：

![定位音频](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_04_01.jpg)

对于场景中的每个音频源和听者，我们存储位置、方向和速度等信息。使用这些信息，音频引擎通过多种方式实时修改所有声音来产生 3D 音频模拟：

+   **位置**：声源的音量会随着到听者的距离增加而减小并变得沉闷（通过过滤声音以减弱一些较高频率）。用于计算给定距离下声音音量的公式通常可通过选择最小和最大距离以及衰减模型来控制。

+   **方向**：根据听者相对于每个声源的方向，音频引擎使用扬声器布置（例如 5.1 环绕声系统）或声像定位（立体声系统）来模拟声音方向和位置。音频源也可以被定向，通常通过定义声音投影锥，包括方向和角度信息。然后，对于站在锥体范围之外的听者，声音会被衰减。

+   **速度**：如果音频源相对于听者移动，声音的音调会发生变化（随着实体靠近而增加，随着实体远离而减少），这是多普勒效应的结果。你可以在现实世界中听到这种效果，例如，当救护车经过你身边时，它的警报器打开，当救护车经过你的位置时，警报器的音调会突然下降。

# FMOD 中的定位音频

在 FMOD 中使用定位音频与我们迄今为止所做的并没有太大不同。事实上，我们已经在前几章中使用了所有需要定位音频的类；`FMOD::Channel`类已经作为音频源工作，而`FMOD::System`类控制场景中的所有音频听者。让我们将整个过程分解为步骤。

## 创建音频源

我们必须记住的第一点是要使用`FMOD_3D`标志来创建我们的声音；否则，3D 音频引擎将不会处理它们：

```cpp
system->createSound("explosion.wav", FMOD_3D, 0, &sound);
```

然后我们只需要像往常一样播放声音，存储通道句柄的引用，以便我们可以修改声音的 3D 属性。

## 设置音频源的位置和速度

播放声音并获得通道句柄后，我们可以使用`set3DAttributes`方法设置音频源的位置和速度：

```cpp
FMOD_VECTOR position = { 3.0f, 4.0f, 2.0f };
FMOD_VECTOR velocity = { 1.0f, 0.0f, 0.0f };
channel->set3DAttributes(&position, &velocity);
```

通常在创建音频源时设置这些值，并在每帧或每次与音频源相关的游戏对象改变其位置或速度时更新它们。

默认情况下，位置以米为单位，速度以每秒米为单位（通常在物理引擎中看到）。我们可以通过在`System::set3DSettings`方法中设置不同的`distancefactor`参数来改变这个比例。

请注意，简单地将对象的位置减去其在上一帧的位置并不会产生以米每秒为单位的速度，这是必需的。如果我们需要使用这种方法，例如因为我们不知道对象的实际速度，我们必须首先将这个增量乘以自上一帧以来经过的时间（以秒为单位）：

```cpp
FMOD_VECTOR velocity;
velocity.x = (position.x - lastPosition.x) * elapsed;
velocity.y = (position.y - lastPosition.y) * elapsed;
velocity.z = (position.z - lastPosition.z) * elapsed;
```

## 设置音频源的方向

默认情况下，每个声音源都是全向的，这意味着声音在每个方向上都是均匀发射的。我们可以通过定义一个投影锥来给声音源一个方向，使用`set3DConeOrientation`和`set3DConeSettings`方法：

```cpp
FMOD_VECTOR direction = { 1.0f, 2.0f, 3.0f };
channel->set3DConeOrientation(&direction);
channel->set3DConeSettings(30.0f, 60.0f, 0.5f);
```

`set3DConeOrientation`方法接受一个定义声音锥主方向的向量。`set3DConeSettings`方法接受三个参数，包含声音锥的内角、外角和外音量。当听者在内角范围内时，声音源以全音量播放，并且随着听者移出该角度而朝向外音量衰减。

## 设置音频源的范围

我们可以使用`set3DMinMaxDistance`方法控制声音仍然可听到的整体距离：

```cpp
channel->set3DMinMaxDistance(1.0f, 10000.0f);
```

我们将声音的范围指定为一对值：最小距离和最大距离。最小距离是声音开始衰减的点。如果听者比最小距离更靠近源，声音将以全音量播放。最大距离是声音停止衰减并保持恒定音量的点（不一定是零音量）。

在最小和最大距离之间音量变化的方式被称为**衰减模型**。默认情况下，FMOD 使用**对数衰减**，随着最小距离的比例而衰减音量：

```cpp
volume = min / distance;
```

通过改变最小距离，我们可以控制声音的整体大小（例如，我们可以为苍蝇的声音设置 0.1 的值，或者为爆炸的声音设置 500 的值）。在使用这个模型时，最大距离应该有一个较大的值，以便让声音有足够的距离衰减到静音。我们可以通过改变`rolloffscale`参数在`System::set3DSettings`方法中使声音衰减得更慢或更快。

对数模型是现实的，但缺点是使得计算声音的完整范围（即静音的距离）更加困难。因此，还有其他可用的模型，比如`linear`衰减模型，它将最小距离映射到全音量，最大距离映射到静音，并在两者之间进行线性插值。我们可以在创建声音时选择`linear`衰减模型，通过添加`FMOD_3D_LINEARROLLOFF`标志。在这个模型中，系统衰减比例不起作用：

```cpp
if (distance <= min) volume = 1.0
else if (distance >= max) volume = 0.0
else volume = (distance - min) / (max - min);
```

## 设置音频监听器的属性

最后，我们必须使用`system`对象的`set3DListenerAttributes`方法设置音频监听器的位置、速度和方向：

```cpp
FMOD_VECTOR pos = { 3.0f, 4.0f, 2.0f };
FMOD_VECTOR vel = { 1.0f, 0.0f, 0.0f };
FMOD_VECTOR forward = { 1.0f, 0.0f, 0.0f };
FMOD_VECTOR up = { 0.0f, 1.0f, 0.0f };
system->set3DListenerAttributes(0, &pos, &vel, &forward, &up);
```

这与设置音频源的属性非常相似，除了增加了方向。方向被指定为一对归一化的垂直向量，指向监听器的上方和前方（通常可以从摄像机对象或视图变换矩阵中获取）。

第一个参数是一个索引，用于标识音频监听器。默认情况下，场景中只有一个音频监听器，所以我们使用值`0`。如果我们需要多个音频监听器，可以使用`system`对象的`set3DNumListeners`方法来增加该数量。

## 与游戏的整合

解决这个问题有几种方法，取决于游戏引擎使用的架构，但通常的过程是为每个可以发出声音的游戏对象分配一个音频源，并为摄像机对象分配一个音频监听器。然后，在游戏循环的更新阶段，每当我们改变游戏对象或摄像机的位置、速度或方向时，我们必须跟随相应的音频结构进行更新。最后，在更新阶段结束时，我们更新音频系统，处理对源和监听器所做的所有更改，并相应地更新模拟。

# 混响

定位音频（包括衰减、扬声器放置和多普勒效应）构成了 3D 音频的最基本层次。现在我们将介绍一些高级技术，可以在定位音频的基础上提供更完整的模拟声音与环境互动的方法之一就是**混响**。

混响是声音在原始声音停止后在特定空间内持续存在一段时间的能力。我们可以将混响看作是一系列回声，它们之间的时间非常短。

混响发生是因为大多数音频源同时在多个方向投射声音。其中一些声波直接到达我们的耳朵，走最短的路径。然而，其他声波朝着不同的方向传播，并在到达我们的耳朵之前反射在各种表面上，比如墙壁。这些反射的声波需要更长的时间才能到达我们的耳朵，而且每次反射都会变得更加安静。所有反射声波的组合产生了混响的效果。

![混响](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_04_02.jpg)

在游戏中模拟混响可以增强场景的真实感，因为它提供了关于环境的大小和性质的强烈线索。例如，一个空荡荡的大教堂，有着大面积的反射墙，通常会产生大量的混响。另一方面，一个没有墙壁的室外位置几乎没有混响。我们还可以通过混响的持续时间推断房间的大小，因为声波在大房间中需要比在小房间中更长的时间传播。

# FMOD 中的混响

如果我们已经在场景中使用了定位音频，那么在 FMOD 中添加混响只需要几行额外的代码。

## 创建混响对象

首先，我们需要使用`createReverb`方法创建一个`FMOD::Reverb`对象：

```cpp
FMOD::Reverb* reverb;
system->createReverb(&reverb);
```

这将创建一个混响区域，自动对站在该区域内的听者可以听到的每个声音应用混响。可以同时安全地创建多个混响区域，因为 FMOD 会自动合并它们的效果。

要禁用混响区域，可以使用`setActive`方法。或者，如果不再需要该区域，可以使用`release`方法永久销毁它：

```cpp
reverb->setActive(false);       // Disable temporarily
reverb->release();              // Destroy reverb
```

## 设置混响属性

混响有许多属性可以自定义其行为。这些属性定义在`FMOD_REVERB_PROPERTIES`结构中，并可以使用`setProperties`方法应用于混响对象。幸运的是，FMOD 还提供了一组预设，例如`FMOD_PRESET_CONCERTHALL`，可以直接使用：

```cpp
FMOD_REVERB_PROPERTIES properties = FMOD_PRESET_CONCERTHALL;
reverb->setProperties(&properties);
```

## 设置混响位置和半径

我们可以使用`set3DAttributes`方法指定混响的位置和范围。混响的范围由最小半径（在该半径内混响以全音量播放）和最大半径（在该半径外混响被禁用）来指定。

```cpp
FMOD_VECTOR position = { 10.0f, 0.0f, 0.0f };
reverb->set3DAttributes(&position, 10.0f, 20.0f);
```

## 设置默认环境混响

我们还可以使用`system`对象的`setReverbAmbientProperties`方法设置当听者不在任何混响区域内时使用哪些混响属性。

```cpp
FMOD_REVERB_PROPERTIES properties = FMOD_PRESET_OFF;
system->setReverbAmbientProperties(&properties);
```

# 遮挡和遮蔽

环境中的障碍物，如大型物体或墙壁，也会改变我们对声音的感知方式。我们经常可以听到在相邻房间说话的人，但声音不如站在我们旁边时清晰。原因是尽管声音可以穿过几种材料，但在这个过程中会失去能量和一些更高的频率。这导致声音变得更安静、沉闷。用于模拟 3D 音频中障碍物的两种技术是**遮挡**和**遮蔽**。

当源和听者在同一环境中，并且有障碍物挡住了去路，但障碍物周围仍有足够的空间让声波流动时，就会发生遮挡。在这种情况下，直接穿过障碍物的声波会被衰减和过滤，但反射的声波不受影响。

当源和听者处于不同的环境，并且所有声音需要通过障碍物（如墙壁）才能到达听者时，就会发生遮挡。在这种情况下，直接和反射的声波都会被衰减和过滤。

应用于遮挡或遮蔽声波的滤波器通常是低通滤波器，它会衰减更高的频率，导致声音变得沉闷。

![遮挡和遮蔽](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_04_03.jpg)

## FMOD 中的遮挡和遮蔽

我们可以使用内置的几何引擎在 FMOD 中模拟遮挡和遮蔽。这仅在我们已经设置好音频源和听者时才有效。之后，我们需要创建几何对象来表示环境中的障碍物。

创建这些对象的最简单方法是从障碍物的 3D 三角网格表示开始。然后，使用`createGeometry`方法创建一个`FMOD::Geometry`实例，足够大以存储所有的三角形和顶点：

```cpp
FMOD::Geometry* geometry;
system->createGeometry(numTriangles, numVertices, &geometry);
```

接下来，对于我们网格中的每个三角形，我们使用`addPolygon`方法向几何对象添加一个新的多边形。前两个参数控制执行的遮挡和遮挡量。第三个参数决定多边形是否应为双面的。第四个参数是多边形中的顶点数，第五个参数是多边形数据本身。第六个参数返回一个索引，可以用来对多边形执行进一步的操作。

```cpp
FMOD_VECTOR vertices[3]; // Fill with triangle vertices
int polygonIndex; // Gets an index for the new polygon
geometry->addPolygon(0.5f, 0.5f, false, 3, vertices, &polygonIndex);
```

我们应该使用对象空间中的顶点创建多边形，而不是世界空间中的顶点。然后，为了将几何体定位到世界中，我们可以使用`setPosition`，`setRotation`和`setScale`方法的组合。

# 效果

除了之前描述的所有 3D 音频模拟，还有另一个主题我们应该涵盖：DSP 效果。**DSP**效果（代表**数字信号处理**）是一种算法，它以声音数据作为输入，以某种方式修改它，并返回一组新的数据作为输出。大多数效果要么操纵声音数据的振幅或频率，要么将多个声音叠加在一起（通常是其自身的延迟和衰减版本）。以下是一些常见类型的 DSP 效果的列表：

+   **归一化**：此效果缩放声音的音量，使峰值幅度达到最大音量水平。

+   **压缩器**：此效果使声音的响亮部分变得更安静，然后将整个音量提高以补偿，减少声音的动态范围

+   **失真**：此效果扭曲声音，使其听起来更刺耳

+   **低通滤波器**：此效果削弱了声音中所有超过一定范围的频率，使声音变得沉闷

+   **高通滤波器**：此效果削弱了声音中所有低于一定范围的频率，使声音变得更薄。

+   **参数均衡器**：此效果在声音的所有不同频率范围上提供复杂的音量控制

+   **延迟**：在此效果中，声音播放一次，并在一定时间后重复播放，直到能量耗尽

+   **回声**：在此效果中，延迟的持续时间足够长，我们可以将其感知为单独的声音

+   **镶边**：此效果在每个实例之间增加了非常小的延迟的声音，并随时间变化这个延迟

+   **合唱**：此效果将声音的多个实例一起播放，它们之间有小的音高和时间变化

+   **音调转换**：此效果改变声音的音调，而不改变其播放速度

+   **去噪**：此效果将低于一定音量阈值的每个值静音

## FMOD 中的效果

再次，我们只会在这里涵盖最基本的内容。在 FMOD 中创建 DSP 效果的最简单方法是使用`createDSPByType`方法，其中一个可用的 DSP 类型作为参数（检查 FMOD 文档以获取完整的类型列表）。

```cpp
FMOD::DSP* dsp;
system->createDSPByType(FMOD_DSP_TYPE_ECHO, &dsp);
```

这将返回一个`FMOD::DSP`对象，您可以使用相应对象的`addDSP`方法将其应用于任何通道、通道组或`system`对象本身。您还可以将多个 DSP 效果添加到同一对象中，这将自动将它们链接在一起：

```cpp
channel->addDSP(dsp, 0);
```

第二个参数允许更多地控制 DSP 连接，但我们将在我们的简单示例中忽略它。

最后，大多数 DSP 效果都有一组参数，您可以使用`setParameter`方法来控制（再次，检查文档以获取所有可用参数的列表）：

```cpp
dsp->setParameter(FMOD_DSP_ECHO_DECAYRATIO, 0.75f);
```

## 示例 1 - 时间拉伸

作为 DSP 效果的第一个应用，这里有一个示例，显示了如何改变声音的播放速度而不影响其音调。为此，我们需要将常规频率变化与音调转换 DSP 效果相结合，以将音调恢复正常。

```cpp
// Play at half speed
float amount = 0.5f;

// Modify frequency which changes both speed and pitch
float frequency;
channel->getFrequency(&frequency);
channel->setFrequency(frequency * amount);

// Create a pitch shift DSP to get pitch back to normal
// by applying the inverse amount
FMOD::DSP* dsp;
system->createDSPByType(FMOD_DSP_TYPE_PITCHSHIFT, &dsp);
dsp->setParameter(FMOD_DSP_PITCHSHIFT_PITCH, 1.0f / amount);
dsp->setParameter(FMOD_DSP_PITCHSHIFT_FFTSIZE, 4096);

// Now only the speed will change
channel->addDSP(dsp, 0);
```

## 示例 2 - 简单的无线电效果

您还可以结合多种效果来实现更复杂的行为。例如，这里有一个简单的收音机效果模拟，它通过对声音应用失真和高通滤波器来实现。

```cpp
FMOD::DSP* distortion;
system->createDSPByType(FMOD_DSP_TYPE_DISTORTION, &distortion);
distortion->setParameter(FMOD_DSP_DISTORTION_LEVEL, 0.85f);

FMOD::DSP* highpass;
system->createDSPByType(FMOD_DSP_TYPE_HIGHPASS, &highpass);
highpass->setParameter(FMOD_DSP_HIGHPASS_CUTOFF, 2000.0f);

channel->addDSP(distortion, 0);
channel->addDSP(highpass, 0);
```

失真模拟了模拟模拟信号传输时经常发生的信息丢失，而高通滤波器通过去除较低频率使声音变得更薄。

# 总结

在本章中，我们已经看到了如何模拟声音来自环境中特定位置，如何模拟反射声波产生的混响，如何模拟障碍物的阻挡和遮挡，最后如何对声音应用数字信号处理效果。


# 第五章：智能音频

到目前为止，我们以非常线性的方式播放声音；我们从磁盘加载音频文件，并在需要时播放它，可以在播放过程中控制一些参数。即使我们使用了高级功能，比如 3D 音频，声音和音频文件之间仍然是一对一的关系。

然而，一个声音不一定对应一个单独的音频文件。在许多情况下，我们可以受益于为单个声音使用多个音频文件。例如，我们通常可以通过提供几种不同的声音变体作为单独的音频文件来减少重复，或者我们可以通过组合几个较小的声音片段来构建复杂的音景。

对于其他声音，我们在运行时应用到它们的参数的修改和构成它们的音频文件一样重要。例如，我们无法真实地模拟汽车引擎的声音，而不是根据发动机的转速和负载值不断更新其音调和音量。另一个常见的例子是，让配乐动态地对游戏中的事件做出反应，以向玩家传达更多或更少的紧张感。

作为程序员，我们当然可以通过为每种情况编写专门的代码来实现这些功能，根据需要编排每个音频文件和声音参数。然而，这种方法需要大量的工作量，而且很难管理和调整，因为大部分行为都是硬编码到游戏中的。更大的问题是，通常是声音设计师而不是程序员为游戏创建声音，使用这种方法需要双方之间大量的沟通和同步。

幸运的是，我们可以通过使用高级音频引擎来解决这个问题。这些引擎通常提供一个外部工具，声音设计师可以使用它来创建复杂的声音，独立于程序员，并将它们存储为声音事件。然后，无论声音的复杂性如何，程序员都可以轻松地从游戏中触发它，通常是通过编写事件的名称。

涵盖这个主题的主要困难在于有几个高级音频引擎可用，每个引擎都有自己的一套功能和理念。使用这些工具，我们可以执行诸如生成音频（根据一组声音样本和规则在运行时生成音频）或自适应音乐（根据游戏事件变化的音乐）等操作。为了简化术语，我们将使用智能音频这个术语来涵盖所有声音可以附加复杂行为的情况。

在本章中，我们将使用 FMOD Designer 工具，并了解一些有趣的东西。由于本书的范围有限，详细介绍这个工具是不可能的，但这应该足够给你一些想法，并让你开始。有关更多信息，FMOD Designer 工具附带了一个超过 400 页的用户手册和一个包含许多示例的示例项目。

# 音频文件与声音事件

在安装 FMOD Designer 工具之前，让我们真正理解将每个音频文件视为声音与以更高的抽象级别处理声音事件（或一些引擎中的声音提示）之间的区别。以下图表展示了迄今为止我们在游戏中处理音频的方式：

![音频文件与声音事件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_01.jpg)

在这个模型中，我们可以看到游戏直接与音频文件交互，代码负责以适合游戏的方式使用这些音频文件，通常需要创建专门的代码。当我们转向使用 FMOD Designer 等高级音频引擎时，这个过程是完全不同的，如下图所示：

![音频文件与声音事件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_02.jpg)

这种模型的第一个区别是游戏不直接与音频文件交互。相反，它与称为声音事件的实体交互，这些实体可能包含多个音频文件，并封装了以前在游戏中的所有自定义行为和参数的声音。这种分离使游戏代码变得简单得多，并为声音设计师提供了更好的工作环境。

还要注意，有一个将所有声音事件组合在一起的音频项目文件。这意味着游戏只需要加载这一个文件就可以访问所有声音事件，这比加载每个单独的音频文件要容易得多。

# 介绍 FMOD Designer

FMOD Designer 是高级的、数据驱动的 API，它补充了我们迄今为止使用的 FMOD Ex 低级引擎。它包含两个部分：

+   **FMOD Designer**：这是一个声音设计师工具，允许我们为我们的游戏创建复杂的声音事件和交互式音乐（来自[`www.fmod.org`](http://www.fmod.org)）

+   **FMOD 事件系统**：这是一个应用层，让我们可以在游戏中使用设计师创建的内容（与 FMOD Ex 捆绑在一起，位于`fmoddesignerapi`文件夹内）

FMOD Designer 项目的文件扩展名为`.fdp`，但要在游戏中使用它们，必须首先从**项目**菜单中构建它们。构建过程会生成一个`.fev`文件，其中包含项目中每个声音事件的所有信息，以及项目中每个波形库的一个`.fsb`文件，其中存储着音频文件。以下是 FMOD Designer 用户界面的截图：

![介绍 FMOD Designer](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_03.jpg)

FMOD Designer 最重要的任务是创建声音事件。在 FMOD 中有两种类型的声音事件，以及一个交互式音乐系统：

+   **简单事件**：通过简单事件，我们可以创建由多个音频文件组成的声音，并以随机或顺序方式播放它们，一次或多次，以不同的速率，并具有随机的音量或音调变化

+   **多轨事件**：通过多轨事件，我们可以组合我们需要的简单事件（在这种情况下称为**声音定义**），将它们组织成层，对它们应用效果，控制任何给定时间应该播放哪些声音定义，创建自定义参数，并将这些参数链接到声音或效果的任何属性

+   **交互式音乐**：通过交互式音乐系统，我们可以创建由多个片段组成的歌曲（称为**提示**），并使游戏在响应特定事件时在它们之间过渡。除了过渡，我们还可以向音乐中添加装饰，这些装饰与主歌同时播放并与之同步。

在接下来的几节中，我们将简要介绍这两个系统的主要特点和用户界面，以及一些如何在游戏环境中使用它们的想法和示例。由于交互式音乐的范围超出了本书的范围，因此对交互式音乐的讨论将更加肤浅。

# 简单事件

简单事件是最容易使用，也是最不占资源的。因此，我们应该尽量在满足我们要求的情况下使用简单事件。通过简单事件，我们可以：

+   创建由多个音频文件组成的声音

+   按顺序或随机顺序播放音频文件

+   随机化声音属性，如音量或音调

+   控制声音的循环行为

+   同时播放多个音频文件，或在特定间隔播放

要创建一个简单事件，转到**事件**部分，在任何**事件组**上右键单击，然后选择**添加简单事件**选项。如果没有创建**事件组**，我们可以从同一上下文菜单中创建一个。事件组的行为类似于文件夹，用于组织我们所有的事件：

![简单事件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_04.jpg)

选择事件后，下一步是将组成它的音频文件添加到**播放列表**窗格中，可以通过右键单击上下文菜单，或将一些音频文件拖放到其中。如果我们打算以随机顺序播放音频文件，可以通过右键单击上下文菜单或使用窗格左下角的旋钮控制指定每个文件播放的概率：

（简单事件）（img/9099OT_05_05.jpg）

在**播放列表选项**窗格中，我们可以控制音频引擎应该如何从播放列表中选择文件。有三种不同的**播放列表行为**：

+   **随机**：此选项每次随机选择一个音频文件，遵循播放列表中为每个文件分配的权重。我们还可以选择是否允许同一个音频文件连续播放两次。

+   **随机**：此选项随机播放播放列表一次，然后按照该顺序播放音频文件。

+   **顺序**：此选项按照音频文件在播放列表中出现的顺序进行播放。

在**播放列表选项**窗格中，我们还可以找到**声音随机化**部分，它让我们可以对每个文件的起始音量和音调应用一些变化（类似于我们在第三章中实现的内容，*音频控制*）：

（简单事件）（img/9099OT_05_06.jpg）

在控制应该播放多少音频文件以及多频率的**播放选项**窗格中，有四种不同的**播放模式**：

+   **一次性**：此模式选择一个单一的音频文件，并仅播放一次

+   **重复循环**：此模式选择一个单一的音频文件，并多次播放（由**播放计数**参数控制次数）

+   **连续循环**：此模式连续播放多个音频文件，每次选择一个新的（由**循环计数**参数控制要播放的文件数量）

+   颗粒状：这种模式类似于上一个模式，但允许我们控制每个播放的文件之间等待的时间（Grain Interval 参数），可以同时播放多少个文件（Polyphony 参数），以及在声音结束之前要播放的文件总数（Total Grains 参数）！（简单事件）（img/9099OT_05_07.jpg）

最后，界面右侧有一个**属性**窗格，它允许我们控制声音事件的其他几个属性，例如前一章讨论的大多数 3D 音频属性。

## 简单事件示例

以下是一些我们可以使用简单事件丰富游戏中音频的想法。这些想法大多可以在 FMOD Designer 附带的示例项目中找到，所以一定要在那里查找。

### 避免重复的音效

大多数游戏都有一些声音效果会一直播放，比如角色的脚步声或枪声。如果每次都使用完全相同的音频文件，玩家通常会在一段时间后注意到重复，这在大多数情况下是不希望的。使用简单事件，我们可以通过提供一些声音的变化并让音频引擎随机选择一个来轻松地使这些声音效果更有趣和动态。

对声音进行微小的音量和音调变化也可以奇迹般地产生效果，只要变化不足以改变声音的整体特性。音量方面的值通常在-3 dB 左右，音调方面的值通常在+/- 2 个半音左右。

### 创建脚步声循环

我们可以以几种方式在游戏中使用脚步声效。例如，我们可以有一个包含单个脚步声音的音频文件，并在游戏世界中角色每走一步时触发它一次，或者我们可以有一个循环播放的行走声音的音频文件，并在角色行走时不断播放。

第一种方法需要在游戏内进行更多的工作，而第二种方法需要更多的内存，因为音频文件需要更长。使用简单事件，我们可以结合两种方法，通过使用单个脚步的音频文件，并设置事件以执行循环，使用适合特定行走速度的时间间隔。稍后，在处理多轨事件时，我们还将看到一种动态变化行走速度的方法。

我们首先创建一个简单的事件，使用脚步声音文件（遵循之前给出的建议以避免重复），并将播放模式设置为颗粒化。然后我们调整颗粒间隔，使每个脚步之间的时间与角色行走的速度相对应，并增加多音，以便每个脚步都可以发出声音，而不必等待前一个结束。我们还可以设置略有不同的最大和最小颗粒间隔值，以进一步增强声音的变化。

### 创建玻璃破碎声音效果

我们可以使用另一种方法来减少声音效果中的重复，即在运行时将它们生成为几个较小的声音片段的组合。例如，为了模拟玻璃物体掉落并破碎的声音，我们可以有一个不同的玻璃破碎声音池，并且总是快速连续地播放其中的两三个声音。结合通常的音量和音调变化，结果是一个大部分时间听起来不同的声音效果。

为了实现这种类型的声音效果，我们需要使用颗粒化播放模式，并将多音和颗粒计数参数设置为我们想要同时使用的声音片段数量。对于玻璃破碎声音效果，我们可以将多音和颗粒计数设置为 2 或 3，并设置一个非常小的颗粒间隔（例如 200 毫秒），以便声音几乎同时播放。

### 创建鸟鸣环境音轨

用于生成玻璃破碎声音的相同技术也可以生成长时间、循环且不断变化的环境音轨。一个常见的例子是取几个小的鸟鸣音频文件，通过在不同时间随机触发它们，并以不同的音量和音调，我们可以轻松地给人一种在森林中的印象，那里有几只不同的鸟在歌唱。该过程与之前的效果非常相似，只是这次我们应该设置一个大的多音（例如 15），大约 1 秒的颗粒间隔值，以及一个无限的颗粒计数，以便声音不会停止播放。修改 3D 位置随机化属性也可以用来创建体积感的声音，并给人一种每只鸟都位于空间中的不同点的印象，而不是每个声音都来自同一个位置。

# 多轨事件

多轨事件比简单事件更强大。事实上，在向多轨事件添加任何声音之前，我们必须将其转换为声音定义，它几乎具有与简单事件相同的功能。使用多轨事件，我们可以：

+   执行我们可以用简单事件完成的一切

+   创建多层声音，同时播放

+   为每个层应用一个或多个 DSP 效果

+   创建自定义参数以实时修改声音

+   根据参数值播放不同的声音

+   通过参数修改任何声音或效果属性

在创建多轨事件之前，我们必须为我们打算使用的每个声音准备一个声音定义。该过程类似于创建简单事件，尽管界面有些不同。转到**声音定义**部分，在任何文件夹上右键单击，并选择**添加声音定义**选项之一：

![多轨事件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_08.jpg)

用于创建声音定义的界面有点像简单事件界面的简化版本，左侧是播放列表，右侧是其他所有属性。由于大多数属性控制的是我们已经在简单事件中看到的内容，因此在这里不需要重复这些信息：

![多轨事件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_09.jpg)

要创建多轨事件，请按照创建简单事件的相同步骤，但选择**添加多轨事件**选项。

![多轨事件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_10.jpg)

多轨事件分为层或轨道，每个层可以包含多个声音定义。通过右键单击以下界面并从上下文菜单中选择**添加层**或**添加声音**选项来添加新层或向层添加声音：

![多轨事件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_11.jpg)

默认情况下，前面的示例将同时播放所有三个声音定义。只要我们在声音上添加参数，这种行为就会改变，可以通过右键单击声音区域顶部的黑暗区域，并从列表中选择**添加参数**选项来完成：

![多轨事件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_12.jpg)

参数本质上是一个具有一定范围允许值的变量，游戏代码可以修改。FMOD Designer 表示参数的方式可能看起来像时间轴，但重要的是要理解参数是一个通用值，并不一定代表时间。

我们创建的第一个参数标记为**主要**参数，并确定要播放哪些声音。在下面的示例中，只有与红线（代表**主要**参数的当前值）接触的两个声音将会播放。将参数的值更改为大于 0.5 的任何值将用**蛙鸣**声替换**蟋蟀**声。我们可以在同一个事件中创建多个参数，尽管其中只有一个会被标记为主要：

![多轨事件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_13.jpg)

参数的另一个用途是控制每个层的声音属性。为了做到这一点，我们必须首先通过右键单击层并选择**添加效果**选项来向要控制的层添加效果。效果可以从简单的音量或音高控制到更复杂的 DSP 效果，如失真或延迟：

![多轨事件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_14.jpg)

在层上添加效果并选择参数后，我们可以在层上绘制曲线，表示效果的属性应该随参数值的变化而变化。在下面的示例中，我们向事件添加了第二个参数，它修改了第一层的音高和第二层的音量：

![多轨事件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_15.jpg)

最后，通过右键单击多轨事件中的任何声音，我们可以访问一些其他地方无法使用的声音实例属性。在这些属性中，有一个自动音高特性，它的行为类似于向该声音添加音高效果，并根据参数进行控制，但使用起来更简单。当尝试模拟汽车引擎的声音时，这个特性非常有用：

![多轨事件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_16.jpg)

## 多轨事件的示例

以下是一些关于如何在游戏中提供更具交互性和动态性的游戏音频体验的多轨事件的想法。其中许多想法是基于之前讨论的简单事件的想法。

### 创建交互式的脚步声音循环

在前一节的简单事件示例中，描述了如何生成循环的脚步声音。然而，该声音仅适用于特定的行走速度和特定的地面。使用多轨事件，我们可以创建一个单一的声音事件，其中包含所有不同类型地面的脚步声音，比如草地、混凝土或沙地，并允许游戏通过参数来控制行走速度。

为了实现这一点，我们首先必须为角色可以行走的每种地面类型创建一个声音定义。每个声音定义应该以平均行走速度播放脚步声音循环，我们可以通过生成速率参数来控制这个速度（这个速度应该在每个声音定义之间保持一致）。

然后，我们必须创建一个多轨事件，其中包含一个图层和两个参数来控制地面类型（主要）和行走速度。通过将所有声音添加到这个图层中，均匀分布它们（通过右键单击并选择**均匀布局声音**选项），并将`surface type`参数的最大范围设置为图层中声音的总数，我们可以使用该参数作为简单的索引来选择角色所行走的地面类型。

对于`walking speed`参数，我们需要向图层添加一个`Spawn Intensity`类型的效果，并绘制一条曲线来控制生成强度与`walking speed`参数的关系。例如，数值为 0.5 意味着脚步声将以平均速度的一半发生，而数值为 2.0 意味着脚步声将以平均速度的两倍发生。

### 模拟汽车引擎的声音

我们还可以使用多轨事件来生成复杂的交互声音，比如汽车引擎的声音。FMOD Designer 示例项目中有一个很棒的汽车引擎模拟，我们可以学习。该声音事件有两个图层和两个参数，一个用于引擎的转速，另一个用于引擎的负载。

每个图层包含四种不同的声音，这些声音是从汽车引擎在不同转速范围内录制的。顶层的声音对应汽车加速（负载），而底层的声音对应汽车减速（卸载）。

`load`参数用于在运行时混合两个图层，并产生音量效果。当`load`参数处于中间时，我们听到两个图层的混合声音，但随着`load`参数的变化，音量迅速变化，以至于我们只听到其中一个图层的声音。

`rpm`参数有两个作用。作为主要参数，它确定当前数值应该播放哪四种声音中的哪一种。实际上，这些声音在边缘处重叠，因此在某些转速数值下，我们可以同时听到两种声音的混合。`rpm`参数的另一个作用是修改声音的音调，因此转速数值越高，声音的音调就越高。这是通过在每个声音上启用**自动音调**功能来自动处理的：

![模拟汽车引擎的声音](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_05_17.jpg)

### 创建一个复杂的森林环境音轨

使用一个简单的事件，我们能够创建一个循环的环境音轨，其中有大量的鸟鸣声。使用多轨事件，我们可以轻松地扩展环境音轨，以包含其他声音图层。例如，我们可以添加一个包含背景中风声循环的声音图层，以及其他类型动物的叫声图层，这些叫声可能以不同的速率发生，与鸟鸣声不同。

如果我们想要在森林中模拟一个洞穴，我们可以创建一个参数来控制角色的位置，并为每个图层添加一个遮蔽效果，该效果仅在一定数值范围内有效。

此外，我们可以创建一个参数来指定一天中的时间，并根据其数值播放不同的声音，比如在夜晚消除鸟鸣声，并加入一些蟋蟀的声音。

# 交互音乐

就像我们可以创建根据游戏事件而改变的复杂音效一样，也可以对游戏的背景音乐做同样的事情。这使得音乐可以适应环境，例如，在危险临近时传达正确的情感，或者提供紧张感。

以这种非线性方式播放的音乐被称为交互式音乐（如果玩家直接控制变化）或自适应音乐（如果音乐对游戏环境做出反应，但不一定对玩家做出反应）。创建交互式音乐有两种主要方法。

## 垂直方法（重新编排）

在这种方法中，音频系统根据游戏中发生的事件实时修改歌曲的混音。例如，可以向歌曲添加新乐器，或者使音乐播放速度更快或更慢以匹配游戏玩法。

在 FMOD Designer 中实现这种类型的交互式音乐最简单的方法是使用多轨事件结合特别准备的多声道音频文件（可以使用 Audacity 等音频编辑软件创建）。这通常需要将音乐分成层，并将每个层添加到文件中的不同音频通道中。然后，使用多轨事件上的通道混音效果，我们可以根据参数的值轻松控制每个音频通道的音量。

这种技术最常见的应用是创建“紧张”或“兴奋”参数，使得随着数值的增加，歌曲变得更加紧张（通过添加更多层）。著名的日本作曲家近藤浩治非常喜欢使用这种方法创建交互式音乐。一些最近的例子包括：

+   在《超级马里奥银河》的关卡中，马里奥站在星球上移动的速度完全决定了歌曲的音调、播放速度，甚至演奏的乐器数量。

+   在《塞尔达传说：天空之剑》的市场区域，每个商人都有自己的市场主题变化。当林克接近其中一个商人时，音乐会非常平稳地转换为相应的变化（同时保持正确的主题内相对定位）。

## 水平方法（重新排列）

在这种方法中，音乐根据游戏事件移动或跳转到不同的部分。这通常需要将音乐分成段，以便游戏可以在它们之间进行过渡。当系统不在段之间过渡时，它会保持当前段的循环，音乐会持续播放。

通常需要音乐的速度和拍子信息，以便音频系统可以将过渡与歌曲的节拍或小节同步，以提供更加音乐化的体验。FMOD Designer 中的交互式音乐系统能够以这种方式创建交互式音乐序列。

使用水平方法创建交互式音乐的经典例子是《猴岛传奇 3》中的歌曲《我是个海盗》，玩家实际上可以实时选择角色接下来要唱的歌词。歌曲在玩家做出选择时等待循环，并在之后平稳过渡。

# 从游戏代码中调用声音事件

为了在游戏中测试我们的 FMOD Designer 项目，我们必须首先构建项目，通过选择“从项目构建”菜单或按下 Ctrl + B。这个过程将生成我们必须复制到游戏资产文件夹中的 fev 和 fsb 文件。

接下来，我们必须向我们的 C++项目添加一些额外的依赖项，以便与 FMOD Designer API 进行交互。这些依赖项与 FMOD Ex 程序员 API 一起提供，但我们必须自己添加引用，如下所示：

1.  导航到**C/C++** | **常规**，并将`C:\FMOD\ fmoddesignerapi\api\inc`添加到**附加包含目录**列表中（条目用分号分隔）。

1.  导航到**链接器** | **常规**，并将`C:\FMOD\ fmoddesignerapi\api\lib`添加到**附加库目录**列表中。

1.  导航到**链接器** | **输入**，并将`fmod_event.lib`添加到**附加依赖项**列表中。

1.  导航到**构建事件** | **后期构建事件**，并将`xcopy /y "C:\FMOD\fmoddesignerapi\api\fmod_event.dll” "$(OutDir)”`添加到**命令行**列表中。

1.  从您的代码中包含`<fmod_event.hpp>`头文件。

最后，加载 FMOD Designer 项目，播放声音事件，并修改一些参数的过程，在很多方面与我们在第二章中看到的*音频播放*类似。让我们看看最基本的做法。

首先，我们必须创建和初始化一个`FMOD::EventSystem`对象，并加载项目文件。我们还应该在每一帧调用`update()`方法，并在游戏结束时调用`release()`方法：

```cpp
// Create an event system object
FMOD::EventSystem* eventSystem;
FMOD::EventSystem_Create(&eventSystem);

// Initialize the event system and load the project
eventSystem->init(100, FMOD_INIT_NORMAL, 0, FMOD_EVENT_INIT_NORMAL);
eventSystem->load("project.fev”, 0, 0);

// Update event system every frame
eventSystem->update();

// Release event system when we are done
eventSystem->release();
```

为了播放一个事件，我们必须通过事件的完全限定名称来获取对它的引用，其中包含项目名称、包含事件的事件组的名称和事件本身的名称。然后，我们可以简单地使用`start()`方法来播放事件：

```cpp
// Get a reference to the event
FMOD::Event* event;
eventSystem->getEvent("ProjectName/EventGroupName/EventName”,
                      FMOD_EVENT_DEFAULT, &event);
// Begin playing the event
event->start();
```

最后，如果有一个我们想要修改的参数，我们可以使用事件对象的`getParameter()`方法获取对它的引用，并使用参数对象的`setValue()`方法更改值：

```cpp
// Get a reference to the parameter
FMOD::EventParameter* parameter;
event->getParameter("ParameterName”, &parameter);

// Change the value of the parameter
parameter->setValue(2.0f);
```

# 总结

在本章中，我们看到了声音可以不仅仅是一个音频文件，FMOD 有一个名为 FMOD Designer 的高级工具，我们可以在 FMOD Designer 中创建简单和多轨声音事件，我们还可以将一些概念应用到音乐中，并从我们的应用程序中播放在 FMOD Designer 中创建的声音事件。


# 第六章：低级音频

我们现在已经到达了这本书的最后一章。到目前为止，我们已经在许多不同复杂度和抽象级别上使用了音频，使用了低级和高级音频引擎。这些音频引擎为开发人员提供了宝贵的帮助，我们应该在可能的时候一定要使用它们。在它们的帮助下，我们已经加载和播放了音频文件，学会了如何控制声音参数，在 3D 环境中模拟声音，并创建了复杂的、多层次的、交互式的声音。

然而，在这一章中，我们将假装这些音频引擎不存在，只使用代表计算机中声音的位和字节。然后，我们将以简化形式重新实现 FMOD 为我们处理的许多功能。我们还将简要介绍声音合成，这是使用数学公式生成声音的行为，而不是依赖录制的音频。

这一章的目的是进一步加深我们对声音工作原理的理解，并对音频引擎为我们实现的许多功能有所了解。它也应该作为那些希望在游戏中实现复杂音频功能的人的起点。

# 表示音频数据

在第一章中，*音频概念*，我们讨论了数字音频理论的最重要概念。特别是，我们看到一个简单的数字数组可以表示音频信号，并讨论了 PCM、采样率、位深度和多声道音频等主题。

在这一章中，我们将把所有这些概念付诸实践，所以在继续之前确保你理解了它们。首先，让我们来看一下音频数据的含义，无论是在理论上还是在代码中。

音频数据只不过是一系列数字，表示在均匀的时间间隔内声音波的振幅。然而，有许多种方法可以在计算机上表示数字，取决于用于表示它们的内存量，它们是否应该能够存储负数，以及这些数字是整数还是浮点数。这些差异导致了 C++提供的多种数据类型来存储数字，如`int`、`short`、`float`和`double`。因此，根据所选择的数据类型，音频数据也可以以多种格式存储。

在这一章中，我们将限制自己使用最常见的音频格式，即有符号的 16 位线性 PCM 格式。在这种格式中，每个样本都是一个 16 位有符号整数（在 C++中是`signed short`），幅度范围从最小幅度的-32768 到最大幅度的 32767。为了简化处理 PCM 样本和其他数量时的表示法，我们将使用以下别名：

```cpp
typedef signed short PCM16;
typedef unsigned int U32;
typedef unsigned short U16;
```

在决定使用什么格式之后，我们需要创建一个数组来存储所有的音频样本。数组的大小直接取决于我们想要存储的声音的采样率、持续时间（以秒为单位）和正在使用的声道数，根据以下公式：

```cpp
count = sampling rate * duration * channels
```

例如，假设采样率为 44100 Hz，我们可以创建一个数组来存储精确 1 秒的单声道音频数据，如下所示：

```cpp
// 1 second of audio data at 44100 Hz (Mono)
// count = 44100 Hz * 1 second * 1 channel
PCM16 data[44100];
```

如果我们想要存储立体声信号，我们将需要存储两倍的信息量（同样的思想也适用于更多的声道）。请记住，表示立体声音频数据的最常见方式是在同一个数组中交错存储左声道和右声道的样本：

```cpp
// 1 second of audio data at 44100 Hz (Stereo)
// data[0] = left, data[1] = right, data[2] = left, etc.
// count = 44100 Hz * 1 second * 2 channels
PCM16 data[88200];
```

# 播放音频数据

我们需要一种方法将音频数据提交给声卡，以便我们可以听到生成的声音。我们可以使用非常低级别的音频 API，例如 PortAudio，它提供了与音频设备通信所需的最低功能。但是，FMOD 也完全能够处理此任务，而且由于我们迄今为止一直在使用它，现在改用不同的 API 几乎没有好处。因此，我们将再次使用 FMOD，但仅作为应用程序和硬件之间的桥梁，我们的代码将处理所有处理。

FMOD 允许我们播放用户创建的音频数据的方式是首先使用`FMOD_OPENUSER`标志创建一个声音，并指定一个回调函数来提供音频数据给声音。

我们必须创建并填充一个`FMOD_CREATESOUNDEXINFO`结构，其中包含关于我们将提交的音频数据的一些细节，例如采样率、格式和声道数，以及一个指向提供数据本身的函数的指针。

对于我们所有的示例，我们将使用 44100 Hz 的采样率，使用 16 位 PCM 格式，并且有两个声道（立体声）。阅读有关每个属性的注释以获取更多信息：

```cpp
// Create and initialize a sound info structure
FMOD_CREATESOUNDEXINFO info;
memset(&info, 0, sizeof(FMOD_CREATESOUNDEXINFO));
info.cbsize = sizeof(FMOD_CREATESOUNDEXINFO);

// Specify sampling rate, format, and number of channels to use
// In this case, 44100 Hz, signed 16-bit PCM, Stereo
info.defaultfrequency = 44100;
info.format = FMOD_SOUND_FORMAT_PCM16;
info.numchannels = 2;

// Size of the entire sound in bytes. Since the sound will be
// looping, it does not need to be too long. In this example
// we will be using the equivalent of a 5 seconds sound.
// i.e. sampleRate * channels * bytesPerSample * durationInSeconds
info.length = 44100 * 2 * sizeof(signed short) * 5;

// Number of samples we will be submitting at a time
// A smaller value results in less latency between operations
// but if it is too small we get problems in the sound
// In this case we will aim for a latency of 100ms
// i.e. sampleRate * durationInSeconds = 44100 * 0.1 = 4410
info.decodebuffersize = 4410;

// Specify the callback function that will provide the audio data
info.pcmreadcallback = WriteSoundData;
```

接下来，我们创建一个循环流声音，指定`FMOD_OPENUSER`模式，并将声音信息结构传递给`createStream()`的第三个参数。然后我们可以像平常一样开始播放声音：

```cpp
// Create a looping stream with FMOD_OPENUSER and the info we filled 
FMOD::Sound* sound;
FMOD_MODE mode = FMOD_LOOP_NORMAL | FMOD_OPENUSER;
system->createStream(0, mode, &info, &sound);
system->playSound(FMOD_CHANNEL_FREE, sound, false, 0);
```

只要声音正在播放，音频引擎就会定期调用我们的回调函数，以获取所需的数据。回调函数必须遵循特定的签名，接受三个参数，即我们创建的声音对象的引用，一个用于写入音频数据的数组，以及我们应该写入数据数组的总字节数。它还应该在最后返回`FMOD_OK`。

数据数组由指向 void（`void*`）的指针定义，因为正如我们之前讨论的，数据有许多不同的格式。我们需要将数据数组转换为正确的格式。由于我们使用`FMOD_SOUND_FORMAT_PCM16`创建了声音，因此我们首先必须将数据数组转换为`signed short*`。

另一个重要的细节是`length`参数指定要写入数组的数据量（以字节为单位），但我们的每个样本都是`signed short`，占用 2 个字节。因此，我们应该确保不要向数据数组写入超过`length/2`个样本。

以下是一个回调函数的示例，通过用零填充整个音频缓冲区来输出静音。虽然不是很有趣，但它应该作为一个很好的起点：

```cpp
FMOD_RESULT F_CALLBACK
WriteSoundData(FMOD_SOUND* sound, void* data, unsigned int length) {
  // Cast data pointer to the appropriate format (in this case PCM16)
  PCM16* pcmData = (PCM16*)data;

  // Calculate how many samples can fit in the data array
  // In this case, since each sample has 2 bytes, we divide
  // length by 2
  int pcmDataCount = length / 2;

  // Output 0 in every sample
  for(int i = 0; i < pcmDataCount; ++i) {
    pcmData[i] = 0;
  }

  return FMOD_OK;
}
```

# 加载声音

获取音频数据的最常见方式是从音频文件中读取。然而，正如我们之前所看到的，有许多不同的音频文件格式，从中读取音频数据通常是一个非平凡的任务。这在压缩的音频文件格式中尤其如此，这些格式需要使用某种算法对音频数据进行解码，然后才能在我们的应用程序中使用。一般来说，最好使用音频引擎或外部库来读取音频文件的内容。

出于教育目的，我们将从 WAV 文件中读取音频数据。然而，我们将在假设我们从中读取的 WAV 文件是以规范形式（即，它仅包含格式和数据子块，按顺序排列），并且音频数据存储在没有任何压缩的情况下。在这些条件下，我们知道所有数据都存储在哪里，并且可以简单地索引到文件中进行读取。对于每个 WAV 文件来说，情况肯定不是这样，这将需要更复杂的加载顺序。

WAV 文件格式建立在更通用的 RIFF 文件格式之上。RIFF 文件被分成数据块。每个块以一个 4 个字符的 ASCII 标识符开头，然后是一个描述块中存储了多少数据的 32 位整数。接下来是块的实际数据，这取决于块的类型。

所有 WAV 文件至少包含以下三个块（其中两个被认为是第一个的子块）：

+   一个包含字符串字面值：WAVE 的**RIFF**块

+   一个包含有关音频文件信息的**格式**子块

+   一个包含实际音频数据的**数据**子块

下图显示了标准格式的 WAV 文件的内容。请注意，如果文件包含压缩数据，则格式子块可能包含比下图中所示更多的数据。文件中也可能出现其他块，或以不同的顺序出现：

![加载声音](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_06_01.jpg)

现在我们有一个列出标准 WAV 文件内容的表格，让我们创建一个类来加载和存储我们关心的文件信息（即采样率、位深度、声道数和音频数据）。

与之前在 FMOD 中使用的相同，我们将把这个类命名为`MySound`。为简单起见，类的每个成员都具有公共可访问性，尽管我们可以提供一些访问器方法，同时将数据设置为私有：

```cpp
class MySound {
 public:
  MySound(const char* path);
  ~MySound();

  U32 samplingRate;
  U16 numChannels;
  U16 bitsPerSample;
  PCM16* data;
  U32 count;
};
```

在构造函数中，我们打开音频文件并将所有相关数据读入成员变量。请注意，任何地方都没有错误检查，这只能在前面描述的条件下工作：

```cpp
#include <iostream>
#include <fstream>

MySound::MySound(const char* path) {
  // Open file stream for input as binary
  std::ifstream file(path, std::ios::in | std::ios::binary);

  // Read number of channels and sample rate
  file.seekg(22);
  file.read((char*)&numChannels, 2);
  file.read((char*)&samplingRate, 4);

  // Read bits per sample
  file.seekg(34);
  file.read((char*)&bitsPerSample, 2);

  // Read size of data in bytes
  U32 length;
  file.seekg(40);
  file.read((char*)&length, 4);

  // Allocate array to hold all the data as PCM samples
  count = length / 2;
  data = new PCM16[count];

  // Read PCM data
  file.read((char*)data, length);
}
```

析构函数负责清理在构造函数中分配的用于保存音频数据的内存：

```cpp
MySound::~MySound() {
  delete[] data;
}
```

# 播放声音

现在我们已经将所有音频数据存储在内存中，我们准备开始播放声音。为了做到这一点，我们必须基本上取出数据数组中存储的每个值，并按顺序发送到音频卡（在我们的情况下，使用之前创建的回调方法）。

如果音频数据的格式、采样率和声道数与输出相同，则这个过程就像是将一个数组的值复制到另一个数组中一样简单。然而，如果它们在任何方面有所不同，这个过程就会变得复杂得多，特别是：

+   如果我们的音频数据的采样率与输出不同，我们需要对数据进行重新采样，使其与输出的采样率匹配，否则声音将以我们预期的不同速率播放。这个操作并不是简单的，超出了本章的范围。

+   如果我们的音频数据与输出的格式不同，我们需要先将数据转换为新的格式。例如，我们可能需要将 32 位浮点样本转换为有符号 16 位整数样本。这并不复杂，大部分是需要将数字从一个范围缩放到另一个范围。

+   如果我们的音频数据与输出的声道数不同，我们必须使信号适应新的声道数。将单声道信号适应为立体声很容易，因为我们只需要将数据的副本发送到两个声道。将立体声信号适应为单声道通常涉及将两个声道的值相加，然后将结果除以二。

为了保持我们的示例简单，我们将假设音频数据具有非常特定的格式，因此不需要进行转换：

+   它有 44100 Hz 的采样率，与输出相同

+   它以 PCM16 音频格式存储，与输出相同

+   它只有一个声道（单声道）的数据，尽管输出有两个声道（立体声），这样我们可以看到如何实现声道平移的示例

在这些条件下，我们只需要两样东西来播放声音，我们需要能够访问音频数据，还需要一个变量来跟踪声音的当前位置（即我们已经写了多少个样本），这样我们就知道下一个要写入的样本是哪一个。一旦位置变得大于数据中的样本数，就意味着声音已经播放完毕，我们中断这个过程。

就像我们对声音类所做的那样，让我们也创建一个类来封装与播放声音相关的所有数据和行为，我们将其命名为`MyChannel`：

```cpp
class MyChannel {
 public:
  MyChannel() : sound(0), position(0) {}
  void Play(MySound* mySound);
  void Stop();
  void WriteSoundData(PCM16* data, int count);

 private:
  MySound* sound;
  int position;
};
```

像 FMOD 中的通道一样，我们应该能够为不同的声音重复使用单个通道对象。因此，我们在构造函数中不再需要一个声音对象，而是在`Play()`方法中分配声音对象。这个方法也重置了位置值：

```cpp
void MyChannel::Play(MySound* mySound) {
  sound = mySound;
  position = 0;
}
```

另一方面，`Stop()`方法只是简单地清除了对声音对象的引用：

```cpp
void MyChannel::Stop() {
  sound = 0;
}
```

最后，这个过程中最重要的部分发生在`WriteSoundData()`方法中，这个方法将从音频回调中调用。这个方法接受两个参数，要写入的 PCM 样本数组和这个数组的大小。请注意，这个方法已经期望`data`数组以正确的格式存在，而不是提供给音频回调的`void*`。`count`也指的是数组中的样本数，而不是字节数。代码中有注释解释每一行在做什么：

```cpp
void MyChannel::WriteSoundData(PCM16* data, int count) {
  // If there is no sound assigned to the channel do nothing  
  if(sound == 0) return;

  // We need to write "count" samples to the "data" array
  // Since output is stereo it is easier to advance in pairs
  for (int i = 0; i < count; i += 2) {

    // If we have reached the end of the sound, stop and return
    if(position >= sound->count) {
      Stop();
      return;
    }

    // Read value from the sound data at the current position
    PCM16 value = sound->data[position];

    // Write value to both the left and right channels
    data[i] = value;
    data[i+1] = value;

    // Advance the position by one sample
    ++position;
  }
}
```

使用这个类，我们的音频回调变得简单得多，因为我们可以将大部分工作委托给通道的`WriteSoundData()`方法。在下面的例子中，有一个单一的通道对象，所以我们一次只能播放一个声音，但稍后我们将看到添加支持多个声音以及其他几个功能是多么容易：

```cpp
MyChannel channel;

FMOD_RESULT F_CALLBACK 
WriteSoundData(FMOD_SOUND *sound, void *data, unsigned int length) {
  // Clear output
  memset(data, 0, length);

  // Get data in the correct format and calculate sample count
  PCM16* pcmData = (PCM16*)data;
  int pcmDataCount = length / 2;

  // Tell the channel to write to the output
  channel.WriteSoundData(pcmData, pcmDataCount);

  return FMOD_OK;
}
```

请注意，在前面的例子中，我们首先用`memset`清除了音频缓冲区。这是必要的，因为一旦声音停止播放，我们将不会填充输出值，并且 FMOD 不会在回调调用之间自动清除缓冲区。

使用这种架构播放声音就像实例化声音一样简单，并要求通道对象播放它：

```cpp
MySound* sound = new MySound("explosion.wav");
channel.Play(sound);
```

# 暂停声音

现在，我们已经使用`MySound`和`MyChannel`类实现了播放声音的基本功能，我们可以开始为其添加更多功能。我们将从最简单的开始，暂停声音。

我们必须添加一个成员变量来保存暂停状态，并一些方法来修改它。我们还必须记住在构造函数中将这个值初始化为`false`，并在`Play()`方法中初始化：

```cpp
public:
  bool GetPaused() const { return paused; }
  void SetPaused(bool value) { paused = value }
private:
  bool paused;
```

接下来，我们只需要在`WriteSoundData()`方法的开头添加一个非常简单的条件，这样当声音暂停时它就不会做任何事情。这就是最简单的方式了！

```cpp
void MyChannel::WriteSoundData(PCM16* data, int count) {
  if(sound == 0 || paused) return;
  for (int i = 0; i < count; i += 2) {
    if(position >= sound->count) {
      Stop();
      return;
    }
    PCM16 value = sound->data[position];
    data[i] = value;
    data[i+1] = value;
    ++position;
  }
}    
```

# 循环播放声音

我们将要实现的下一个功能是无限循环播放声音的能力。像暂停声音的能力一样，这也是相当容易实现的。我们首先重复为暂停所做的一切，但是为了循环播放：

```cpp
public:
  bool GetLoop() const { return loop; }
  void SetLoop(bool value) { loop = value }
private:
  bool loop;
```

在`WriteSoundData()`方法中，我们曾经用来检测声音是否已经到达结尾的部分，我们首先检查循环变量是否设置为`true`，如果是这样，我们将位置设置回到开头，而不是停止声音：

```cpp
void MyChannel::WriteSoundData(PCM16* data, int count) {
  if(sound == 0 || paused) return;
  for (int i = 0; i < count; i += 2) {
    if(position >= sound->count) {
      if(loop) {
        position = 0;
      } else {
        Stop();
        return;
      }
    }
    PCM16 value = sound->data[position];
    data[i] = value;
    data[i+1] = value;
    ++position;
  }
}
```

# 改变音量

我们将要实现的下一个功能涉及修改发送到输出的值。改变声音的音量可能是其中最简单的，因为它只需要一个乘法。

让我们首先创建一个变量和一些方法来控制音量。音量将以 0（静音）到 1（最大音量）之间的浮点数存储。`SetVolume()`方法确保该值始终在此范围内。每当声音开始播放时，我们还应该将音量重置为 1：

```cpp
public:
  float GetVolume() const { return volume; }
  void SetVolume(float value) {
    if(value < 0.0f) volume = 0.0f;
    else if(value > 1.0f) volume = 1.0f;
    else volume = value;
  }
private:
  float volume;
```

为了以这种音量播放声音，我们只需将音频数据中的每个原始值乘以音量变量的值，然后将它们写入输出。由于音量变量是浮点数，所以在乘法后需要将结果强制转换回 PCM16：

```cpp
void MyChannel::WriteSoundData(PCM16* data, int count) {
  if(sound == 0 || paused) return;
  for (int i = 0; i < count; i += 2) {
    if(position >= sound->count) {
      if(loop) {
        position = 0;
      } else {
        Stop();
        return;
      }
    }
    PCM16 value = (PCM16)(sound->data[position] * volume);
    data[i] = value;
    data[i+1] = value;
    ++position;
  }
}
```

# 改变音高

改变声音的音高比改变音量稍微复杂一些。修改声音音高的最基本方法（尽管声音的速度也会受到影响）是控制我们如何快速推进位置值。

到目前为止，我们使用了一个整数`position`变量，并且每次增加一个完整的单位。为了提供音高控制，我们将把该变量更改为浮点数，并添加一个`pitch`变量，用于确定增加位置的数量。

默认情况下，`pitch`变量的值将为 1，这将以正常音高播放声音。值为 2 将使声音的频率加倍，使其听起来高一个八度，而值为 0.5 将使声音的频率减半，使其听起来低一个八度。出于实际原因，我们将限制其值在 0.25（原始声音以下两个八度）和 4（原始声音以上两个八度）之间：

```cpp
public:
  float GetPitch() const { return pitch; }
  void SetPitch(float value) {
    if(value < 0.25f) pitch = 0.25f;
    else if(value > 4.0f) pitch = 4.0f;
    else pitch = value;
  }
private:
  float position;
  float pitch;
```

在我们的`WriteSoundData()`方法中，我们按照音高量增加位置变量。在这个过程中最困难的部分是如何将现在是浮点数的`position`变量转换回数组索引。最简单的解决方案是使用简单的强制转换，将值截断为整数，这就是我们将使用的方法：

```cpp
void MyChannel::WriteSoundData(PCM16* data, int count) {
  if(sound == 0 || paused) return;
  for (int i = 0; i < count; i += 2) {
    if(position >= sound->count) {
      if(loop) {
        position = 0;
      } else {
        Stop();
        return;
      }
    }
    PCM16 value = (PCM16)(sound->data[(int)position] * volume);
    data[i] = value;
    data[i+1] = value;
    position += pitch;
  }
} 
```

然而，从强制转换中的截断可能会引入信号失真。例如，如果位置的前进速度比正常慢，那么会有许多值介于整数之间，但由于从强制转换中的截断，我们将多次将相同的值写入输出，而不是流动的声波。

更好的方法是使用线性插值（或其他类型的插值）来计算采样值，考虑周围的值和位置的小数部分。例如，使用线性插值，如果位置是 2.25，我们将输出`data[2]`值的 75%与`data[3]`值的 25%的混合。

# 改变声音定位

有许多不同的方法可以实现声音的立体声定位。在本节中，我们将介绍一种简单的方法，通过独立修改左右声道的音量来实现。

在实际进行任何计算之前，让我们通过添加两个私有变量`leftGain`和`rightGain`来为声音定位做准备，以存储每个声道的音量：

```cpp
private:
  float leftGain;
  float rightGain;
```

然后，在`WriteSoundData()`方法中，我们可以在将数据写入输出之前应用这些增益，就像我们之前对音量做的那样。当然，我们应该只将`leftGain`和`rightGain`的值应用于各自的声道。此外，因为我们需要在应用增益后转换为 PCM16，所以没有必要保留之前的强制转换：

```cpp
void MyChannel::WriteSoundData(PCM16* data, int count) {
  if(sound == 0 || paused) return;
  for (int i = 0; i < count; i += 2) {
    if(position >= sound->count) {
      if(loop) {
        position = 0;
      } else {
        Stop();
        return;
      }
    }
    float value = sound->data[(int)position] * volume;
    data[i] = (PCM16)(value * leftGain);
    data[i+1] = (PCM16)(value * rightGain);
    position += pitch;
  }
}
```

现在，我们需要创建一个名为`pan`的浮点变量，并编写一些方法来修改它。`pan`变量的值应在-1（完全左侧）和 1（完全右侧）之间。每当`pan`的值发生变化时，我们调用私有的`UpdatePan()`方法来计算`leftGain`和`rightGain`的新值。

```cpp
public:
  float GetPan() const { return pan; }
  void SetPan(float value) {
    if(value < -1.0f) pan = -1.0f;
    else if(value > 1.0f) pan = 1.0f;
    else pan = value;
    UpdatePan();
  }
private:
  void UpdatePan();
  float pan;
```

现在剩下的就是编写`UpdatePan()`方法。有几种不同的公式可以计算立体声定位的增益值。其中最简单的方法之一是使用线性定位，其中每个声道从一侧的 0%音量开始，线性增加到另一侧的 100%，同时在中间处于 50%。以下是线性定位的实现：

```cpp
// Linear panning
void MyChannel::UpdatePan() {
  float position = pan * 0.5f;
  leftGain = 0.5f - position;
  rightGain = position + 0.5f;
}
```

另一种方法，通常在平移时产生更平滑的过渡，是使用**恒功率平移**，其中每个通道的音量遵循圆形曲线，每个通道的音量在中间大约为 71%。我们之前已经讨论过恒功率平移，因为它是 FMOD 用于平移单声道声音的平移类型。在不涉及数学细节的情况下，这是恒功率平移的实现：

```cpp
#include <math.h>

#define PI_4 0.78539816339      // PI/4
#define SQRT2_2 0.70710678118   // SQRT(2)/2

// Constant-power panning
void MyChannel::UpdatePan() {
  double angle = pan * PI_4;
  leftGain = (float)(SQRT2_2 * (cos(angle) - sin(angle)));
  rightGain = (float)(SQRT2_2 * (cos(angle) + sin(angle)));
}
```

# 混合多个声音

到目前为止，我们只播放了一个声音，但很容易扩展我们正在做的事情以同时播放多个声音。将多个声音组合成单个输出的行为称为**音频混合**，可以通过将所有音频信号相加并将结果夹紧到可用范围来实现。查看我们的`WriteSoundData()`方法，我们只需要更改写入数据数组的代码行，以便将样本添加到现有值中，而不是完全替换它们：

```cpp
void MyChannel::WriteSoundData(PCM16* data, int count) {
  if(sound == 0 || paused) return;
  for (int i = 0; i < count; i += 2) {
    if(position >= sound->count) {
      if(loop) {
        position = 0;
      } else {
        Stop();
        return;
      }
    }
    float value = sound->data[(int)position] * volume;
    data[i] = (PCM16)(value * leftGain + data[i]);
    data[i+1] = (PCM16)(value * rightGain + data[i+1]);
    position += pitch;
  }
}  
```

在我们的主应用程序中，我们现在可以创建多个实例，然后对它们所有调用`WriteSoundData()`：

```cpp
std::vector<MyChannel> channels;

FMOD_RESULT F_CALLBACK 
WriteSoundData(FMOD_SOUND *sound, void *data, unsigned int length) {
  // Clear output
  memset(data, 0, length);

  // Get data in the correct format and calculate sample count
  PCM16* pcmData = (PCM16*)data;
  int pcmDataCount = length / 2;

  // Tell every channel to write to the output
  for(int i = 0; i < channels.size(); ++i)
    channels[i].WriteSoundData(pcmData, pcmDataCount);

  return FMOD_OK;
}
```

# 实现延迟效果

我们已经在第四章*3D 音频*中讨论过，DSP 效果是修改音频数据以实现特定目标的算法。现在我们将看到如何实现一个简单的延迟效果的示例。基本延迟效果的工作方式是保留一个单独的数据缓冲区，并将已经播放的音频数据存储在其中。缓冲区的大小决定了原始声音和其回声之间的时间间隔。然后，我们只需要将正在播放的音频数据与存储在缓冲区中的旧信号的一部分混合，这样就产生了延迟。让我们来看一下封装了这种效果的`MyDelay`类定义：

```cpp
class MyDelay {
public:
  MyDelay(float time, float decay);
  ~MyDelay();
  void WriteSoundData(PCM16* data, int count);

private:
  PCM16* buffer;
  int size;
  int position;
  float decay;
};
```

`MyDelay`类构造函数接受两个参数，`time`和`decay`。第一个参数控制声音和第一个回声之间的时间间隔。第二个参数控制每个回声中丢失的能量量。

该类存储 PCM16 样本的缓冲区，我们在构造函数中初始化它，以便以 44100 Hz 的采样率存储相当于`time`秒的数据。该缓冲区最初完全填充为零。它还包含一个`position`变量，将用于循环遍历缓冲区：

```cpp
MyDelay::MyDelay(float time, float decay) : position(0), decay(decay)
{
  size = (int)(time * 44100);
  buffer = new PCM16[size];
  memset(buffer, 0, size * 2);
}
```

析构函数删除构造函数中分配的所有数据：

```cpp
MyDelay::~MyDelay() {
  delete[] buffer;
}
```

最后，`WriteSoundData()`方法完成所有工作。它首先获取输出中的每个样本，并将其与当前位置缓冲区中存储的样本的一部分混合。接下来，我们将这个新值写回到输出，以及缓冲区。最后，我们将位置变量递增到下一个样本，绕过缓冲区的末尾：

```cpp
void MyDelay::WriteSoundData(PCM16* data, int count) {
  for (int i = 0; i < count; ++i) {
    // Mix sample with the one stored in the buffer at position
    data[i] = (PCM16)(data[i] + buffer[position] * decay);

    // Record this new value in the buffer at position
    buffer[position] = data[i];

    // Increment buffer position wrapping around
    ++position;
    if(position >= size)
      position = 0;
  }
}
```

要测试这种效果，只需在主应用程序中创建一个实例，并在音频回调结束时调用`WriteSoundData()`方法：

```cpp
// When the application starts
MyDelay* delay = new MyDelay(1.0f, 0.50f);

// Inside the audio callback
for(int i = 0; i < channels.size(); ++i)
  channels[i].WriteSoundData(pcmData, pcmDataCount);
delay->WriteSoundData(pcmData, pcmDataCount);
```

# 合成声音

在结束本章之前，值得意识到并不是每种声音都需要来自音频文件。也可以仅使用数学公式从头开始生成声音。我们称这个过程为**声音合成**，有整本书专门讨论这个主题。

由于某些声波的计算方式非常简单，它们在声音合成中特别常见。我们之前已经讨论过其中一种声波，即正弦波。其他常见的例子包括方波、锯齿波和三角波，都在下图中表示：

![合成声音](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/gtst-cpp-aud-prog-gm-dev/img/9099OT_06_02.jpg)

现在我们将看到如何合成这些声波，通过创建一个名为`MyOscillator`的类。这个类的用例与之前描述的`MyDelay`类几乎相同；只需创建一个实例，并在音频回调中调用`WriteSoundData（）`方法使其播放：

```cpp
#include <math.h>
#define PI 3.14159265359
#define TWO_PI 6.28318530718

class MyOscillator {
 public:
  MyOscillator();
  void SetVolume(double value) { volume = value; }  
  void SetFrequency(double frequency);
  void WriteSoundData(PCM16* data, int count);

 private:
  double phase;
  double increment;
  double volume;
};
```

该类包含三个成员变量，`phase`描述了我们沿着声波走了多远，`increment`取决于声音的频率，并描述了我们在每个样本之间应该推进相位的量，`volume`可以通过`SetVolume（）`方法进行更改。请注意，我们在所有地方都使用双精度而不是浮点数，因为声音合成在计算中需要更多的精度。

类构造函数所做的一切就是将相位初始化为零，音量初始化为一，并通过使用默认值 440 赫兹调用`SetFrequency（）`来设置增量：

```cpp
MyOscillator::MyOscillator() : phase(0.0), volume(0.5) {
  SetFrequency(440.0);
}
```

`SetFrequency（）`方法使用以下公式计算正确的增量值。在这种情况下，我们已经将采样率硬编码为 44100 赫兹，但可以有一个参数来控制采样率：

```cpp
void MyOscillator::SetFrequency(double frequency) {
  increment = frequency / 44100.0 * TWO_PI;
}
```

通常情况下，大部分工作都在`WriteSoundData（）`方法中处理。首先，我们计算当前相位的声波值，并将其缩放到 PCM16 样本的正确范围（通过乘以 32767，这是可以存储在有符号短整数中的最大数）。接下来，我们将这个结果写入音频输出，将其与已经存在的任何内容混合。最后，我们增加相位，并将其包装起来，使其始终保持在 0 到 2 PI 的范围内：

```cpp
void WriteSoundData(PCM16* data, int count) {
  for(int i = 0; i < count; i += 2) {
    // Calculate sample value
    double value = sine_wave(phase) * 32767.0 * volume;

    // Mix sample with output
    data[i] = (PCM16)(data[i] + value);
    data[i+1] = (PCM16)(data[i+1] + value);

    // Increment phase
    phase += increment;

    // Wrap phase to the 0-2PI range
    if(phase >= TWO_PI)
      phase -= TWO_PI;
  }
}
```

实际的音频数据是由前面代码中突出显示的`sine_wave（）`方法生成的。这个方法所做的就是在相位值上调用标准的`sin（）`函数并返回结果。我们可以根据我们想要播放的声波类型，轻松地用以下任何一种实现来替换这个方法：

```cpp
double sine_wave(double phase) {
  return sin(phase);
}

double square_wave(double phase) {
  return phase <= PI ? 1.0 : -1.0;
}

double downward_sawtooth_wave(double phase) {
  return 1.0 - 2.0 * (phase / TWO_PI);
}
double upward_sawtooth_wave(double phase) {
  return 2.0 * (phase / TWO_PI) - 1.0;
}

double triangle_wave(double phase) {
  double result = upward_sawtooth_wave(phase);
  if(result < 0.0)
    result = -result;
  return 2.0 * (result - 0.5);
}
```

# 摘要

在本章中，我们已经看到如何直接处理音频数据的位和字节，如何从经典的 WAV 文件中加载音频数据，如何仅使用低级操作播放和控制音频数据，如何实现简单的延迟效果，以及如何合成一些基本的声波。
