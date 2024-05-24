# C++ 现代嵌入式编程秘籍（四）

> 原文：[`annas-archive.org/md5/5f729908f617ac4c3bf4b93d739754a8`](https://annas-archive.org/md5/5f729908f617ac4c3bf4b93d739754a8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：外围设备

与外围设备的通信是任何嵌入式应用的重要部分。应用程序需要检查可用性和状态，并向各种设备发送数据和接收数据。

每个目标平台都不同，连接外围设备到计算单元的方式有很多种。然而，有几种硬件和软件接口已经成为与外围设备通信的行业标准。在本章中，我们将学习如何处理直接连接到处理器引脚或串行接口的外围设备。本章涵盖以下主题：

+   通过 GPIO 控制连接的设备

+   探索脉宽调制

+   使用 ioctl 访问 Linux 中的实时时钟

+   使用 libgpiod 控制 GPIO 引脚

+   控制 I2C 外围设备

本章的配方涉及与真实硬件的交互，并打算在真实的树莓派板上运行。

# 通过 GPIO 控制连接的设备

**通用输入输出**（GPIO）是将外围设备连接到 CPU 的最简单方式。每个处理器通常都有一些用于通用目的的引脚。这些引脚可以直接与外围设备的引脚电连接。嵌入式应用可以通过改变配置为输出的引脚的信号电平或读取输入引脚的信号电平来控制设备。

信号电平的解释不遵循任何协议，而是由外围设备确定。开发人员需要查阅设备数据表以便正确地编程通信。

这种类型的通信通常是在内核端使用专用设备驱动程序完成的。然而，这并不总是必需的。在这个配方中，我们将学习如何从用户空间应用程序中使用树莓派板上的 GPIO 接口。

# 如何做...

我们将创建一个简单的应用程序，控制连接到树莓派板上的通用引脚的**发光二极管**（LED）：

1.  在你的`~/test`工作目录中，创建一个名为`gpio`的子目录。

1.  使用你喜欢的文本编辑器在`gpio`子目录中创建一个`gpio.cpp`文件。

1.  将以下代码片段放入文件中：

```cpp
#include <chrono>
#include <iostream>
#include <thread>
#include <wiringPi.h>

using namespace std::literals::chrono_literals;
const int kLedPin = 0;

int main (void)
{
  if (wiringPiSetup () <0) {
    throw std::runtime_error("Failed to initialize wiringPi");
  }

  pinMode (kLedPin, OUTPUT);
  while (true) {
    digitalWrite (kLedPin, HIGH);
    std::cout << "LED on" << std::endl;
    std::this_thread::sleep_for(500ms) ;
    digitalWrite (kLedPin, LOW);
    std::cout << "LED off" << std::endl;
    std::this_thread::sleep_for(500ms) ;
  }
  return 0 ;
}
```

1.  创建一个包含我们程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(gpio)
add_executable(gpio gpio.cpp)
target_link_libraries(gpio wiringPi)
```

1.  使用[WiringPI 示例](http://wiringpi.com/examples/blink/)部分的说明，将 LED 连接到树莓派板上。

1.  建立一个 SSH 连接到你的树莓派板。按照[Raspberry Pi 文档](https://www.raspberrypi.org/documentation/remote-access/ssh/)部分的说明进行操作。

1.  通过 SSH 将`gpio`文件夹的内容复制到树莓派板上。

1.  通过 SSH 登录到板上，然后构建和运行应用程序：

```cpp
$ cd gpio && cmake . && make && sudo ./gpio
```

你的应用程序应该运行，你应该能够观察到 LED 在闪烁。

# 工作原理...

树莓派板有 40 个引脚（第一代有 26 个）可以使用**内存映射输入输出**（MMIO）机制进行编程。MMIO 允许开发人员通过读取或写入系统物理内存中的特定地址来查询或设置引脚的状态。

在第六章的*使用专用内存*配方中，*内存管理*，我们学习了如何访问 MMIO 寄存器。在这个配方中，我们将把 MMIO 地址的操作交给专门的库`wiringPi`。它隐藏了内存映射和查找适当偏移量的所有复杂性，而是暴露了一个清晰的 API。

这个库已经预装在树莓派板上，所以为了简化构建过程，我们将直接在板上构建代码，而不是使用交叉编译。与其他教程不同，我们的构建规则没有提到交叉编译器 - 我们将使用板上的本机 ARM 编译器。我们只添加了对`wiringPi`库的依赖：

```cpp
target_link_libraries(gpio wiringPi)
```

这个示例的代码是对`wiringPi`用于 LED 闪烁的示例的修改。首先，我们初始化`wiringPi`库：

```cpp
if (wiringPiSetup () < 0) {
    throw std::runtime_error("Failed to initialize wiringPi");
}
```

接下来，我们进入无限循环。在每次迭代中，我们将引脚设置为`HIGH`状态：

```cpp
    digitalWrite (kLedPin, HIGH);
```

在 500 毫秒的延迟之后，我们将相同的引脚设置为`LOW`状态并添加另一个延迟：

```cpp
 digitalWrite (kLedPin, LOW);
    std::cout << "LED off" << std::endl;
 std::this_thread::sleep_for(500ms) ;
```

我们配置程序使用引脚`0`，对应于树莓派的`BCM2835`芯片的`GPIO.0`或引脚`17`：

```cpp
const int kLedPin = 0;
```

如果 LED 连接到这个引脚，它将会闪烁，打开 0.5 秒，然后关闭 0.5 秒。通过调整循环中的延迟，您可以改变闪烁模式。

由于程序进入无限循环，我们可以通过在 SSH 控制台中按下*Ctrl* + *C*来随时终止它；否则，它将永远运行。

当我们运行应用程序时，我们只会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/9f3a257e-977a-4e63-97e3-c39452e84ce4.png)

我们记录 LED 打开或关闭的时间，但要检查程序是否真正工作，我们需要查看连接到引脚的 LED。如果我们按照接线说明，就可以看到它是如何工作的。当程序运行时，板上的 LED 会与程序输出同步闪烁：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/72b7b80d-860c-48ec-ba6c-bb4aaee983d5.png)

我们能够控制直接连接到 CPU 引脚的简单设备，而无需编写复杂的设备驱动程序。

# 探索脉宽调制

数字引脚只能处于两种状态之一：`HIGH`或`LOW`。连接到数字引脚的 LED 也只能处于两种状态之一：`on`或`off`。但是有没有办法控制 LED 的亮度？是的，我们可以使用一种称为**脉宽调制**（**PWM**）的方法。

PWM 背后的想法很简单。我们通过周期性地打开或关闭电信号来限制电信号传递的功率。这使得信号以一定频率脉冲，并且功率与脉冲宽度成正比 - 即信号处于`HIGH`状态的时间。

例如，如果我们将引脚设置为`HIGH` 10 微秒，然后在循环中再设置为`LOW` 90 微秒，连接到该引脚的设备将接收到原本的 10%的电源。

在这个教程中，我们将学习如何使用 PWM 来控制连接到树莓派板数字 GPIO 引脚的 LED 的亮度。

# 操作步骤如下...

我们将创建一个简单的应用程序，逐渐改变连接到树莓派板上的通用引脚的 LED 的亮度：

1.  在您的`~/test`工作目录中，创建一个名为`pwm`的子目录。

1.  使用您喜欢的文本编辑器在`pwm`子目录中创建一个名为`pwm.cpp`的文件。

1.  让我们添加所需的`include`函数并定义一个名为`Blink`的函数：

```cpp
#include <chrono>
#include <thread>

#include <wiringPi.h>

using namespace std::literals::chrono_literals;

const int kLedPin = 0;

void Blink(std::chrono::microseconds duration, int percent_on) {
    digitalWrite (kLedPin, HIGH);
    std::this_thread::sleep_for(
            duration * percent_on / 100) ;
    digitalWrite (kLedPin, LOW);
    std::this_thread::sleep_for(
            duration * (100 - percent_on) / 100) ;
}
```

1.  接下来是一个`main`函数：

```cpp
int main (void)
{
  if (wiringPiSetup () <0) {
    throw std::runtime_error("Failed to initialize wiringPi");
  }

  pinMode (kLedPin, OUTPUT);

  int count = 0;
  int delta = 1;
  while (true) {
    Blink(10ms, count);
    count = count + delta;
    if (count == 101) {
      delta = -1;
    } else if (count == 0) {
      delta = 1;
    }
  }
  return 0 ;
}
```

1.  创建一个包含我们程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(pwm)
add_executable(pwm pwm.cpp)
target_link_libraries(pwm wiringPi)
```

1.  按照[`wiringpi.com/examples/blink/`](http://wiringpi.com/examples/blink/)中的*WiringPI 示例*部分的说明，将 LED 连接到树莓派板上。

1.  建立 SSH 连接到您的树莓派板。请按照[`www.raspberrypi.org/documentation/remote-access/ssh/`](https://www.raspberrypi.org/documentation/remote-access/ssh/)中的*Raspberry PI 文档*部分的说明进行操作。

1.  通过 SSH 将`pwm`文件夹的内容复制到树莓派板上。

1.  通过 SSH 登录到板上，然后构建和运行应用程序：

```cpp
$ cd pwm && cmake . && make && sudo ./pwm
```

您的应用程序现在应该运行，您可以观察 LED 的闪烁。

# 工作原理...

这个配方重用了从前一个配方中闪烁 LED 的代码和原理图。我们将这段代码从`main`函数移动到一个新函数`Blink`中。

`Blink`函数接受两个参数——`duration`和`percent_on`：

```cpp
void Blink(std::chrono::microseconds duration, int percent_on)
```

`duration`确定脉冲的总宽度（以微秒为单位）。`percent_on`定义了信号为`HIGH`时的时间与脉冲总持续时间的比例。

实现很简单。当调用`Blink`时，它将引脚设置为`HIGH`并等待与`percent_on`成比例的时间：

```cpp
    digitalWrite (kLedPin, HIGH);
    std::this_thread::sleep_for(
            duration * percent_on / 100);
```

之后，它将引脚设置为`LOW`并等待剩余时间：

```cpp
    digitalWrite (kLedPin, LOW);
    std::this_thread::sleep_for(
            duration * (100 - percent_on) / 100);
```

`Blink`是实现 PWM 的主要构建块。我们可以通过将`percent_on`从`0`变化到`100`来控制亮度，如果我们选择足够短的`duration`，我们将看不到任何闪烁。

电视或监视器的刷新率相等或短于持续时间是足够好的。对于 60 赫兹，持续时间为 16.6 毫秒。我们使用 10 毫秒以简化。

接下来，我们将所有内容包装在另一个无限循环中，但现在它有另一个参数`count`：

```cpp
  int count = 0;
```

它在每次迭代中更新，并在`0`和`100`之间反弹。`delta`变量定义了变化的方向——减少或增加——以及变化的量，在我们的情况下始终为`1`：

```cpp
  int delta = 1;
```

当计数达到`101`或`0`时，方向会改变：

```cpp
    if (count == 101) {
      delta = -1;
    } else if (count == 0) {
      delta = 1;
    }
```

在每次迭代中，我们调用`Blink`，传递`10ms`作为脉冲和`count`作为定义 LED 开启时间的比例，因此它的亮度（如下图所示）：

```cpp
    Blink(10ms, count);
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/98a8f41e-0940-43fa-82fe-09b2c45f7fb0.png)

由于更新频率高，我们无法确定 LED 何时从开启到关闭。

当我们将所有东西连接起来并运行程序时，我们可以看到 LED 逐渐变亮或变暗。

# 还有更多...

PWM 广泛用于嵌入式系统，用于各种目的。这是伺服控制和电压调节的常见机制。使用*脉宽调制*维基百科页面，网址为[`en.wikipedia.org/wiki/Pulse-width_modulation`](https://en.wikipedia.org/wiki/Pulse-width_modulation)，作为了解更多关于这种技术的起点。

# 使用 ioctl 访问 Linux 中的实时时钟

在我们之前的配方中，我们使用 MMIO 从用户空间 Linux 应用程序访问外围设备。然而，这种接口不是用户空间应用程序和设备驱动程序之间通信的推荐方式。

在类 Unix 操作系统（如 Linux）中，大多数外围设备可以以与常规文件相同的方式访问，使用所谓的设备文件。当应用程序打开设备文件时，它可以从中读取，从相应设备获取数据，或者向其写入，向设备发送数据。

在许多情况下，设备驱动程序无法处理非结构化的数据流。它们期望以请求和响应的形式组织的数据交换，其中每个请求和响应都有特定和固定的格式。

这种通信由`ioctl`系统调用来处理。它接受一个设备相关的请求代码作为参数。它还可能包含其他参数，用于编码请求数据或提供输出数据的存储。这些参数特定于特定设备和请求代码。

在这个配方中，我们将学习如何在用户空间应用程序中使用`ioctl`与设备驱动程序进行数据交换。

# 如何做...

我们将创建一个应用程序，从连接到树莓派板的**实时时钟**（**RTC**）中读取当前时间：

1.  在您的`~/test`工作目录中，创建一个名为`rtc`的子目录。

1.  使用您喜欢的文本编辑器在`rtc`子目录中创建一个名为`rtc.cpp`的文件。

1.  让我们把所需的`include`函数放到`rtc.cpp`文件中：

```cpp
#include <iostream>
#include <system_error>

#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/rtc.h>
```

1.  现在，我们定义一个名为`Rtc`的类，它封装了对真实时钟设备的通信：

```cpp
class Rtc {
  int fd;
  public:
    Rtc() {
      fd = open("/dev/rtc", O_RDWR);
      if (fd < 0) {
        throw std::system_error(errno,
            std::system_category(),
            "Failed to open RTC device");
      }
    }

    ~Rtc() {
      close(fd);
    }

    time_t GetTime(void) {
      union {
        struct rtc_time rtc;
        struct tm tm;
      } tm;
      int ret = ioctl(fd, RTC_RD_TIME, &tm.rtc);
      if (ret < 0) {
        throw std::system_error(errno,
            std::system_category(),
            "ioctl failed");
      }
      return mktime(&tm.tm);
    }
};
```

1.  一旦类被定义，我们将一个简单的使用示例放入`main`函数中：

```cpp
int main (void)
{
  Rtc rtc;
  time_t t = rtc.GetTime();
  std::cout << "Current time is " << ctime(&t)
            << std::endl;

  return 0 ;
}
```

1.  创建一个包含我们程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(rtc)
add_executable(rtc rtc.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  构建您的应用程序并将生成的`rtc`二进制文件复制到我们的树莓派模拟器中。

# 工作原理...

我们正在实现一个直接与连接到系统的硬件 RTC 通信的应用程序。系统时钟和 RTC 之间存在差异。系统时钟仅在系统运行时处于活动状态并维护。当系统关闭电源或进入睡眠模式时，系统时钟变得无效。即使系统关闭，RTC 也处于活动状态。它维护用于在系统启动时配置系统时钟的实际时间。此外，它可以被编程为在睡眠模式下的特定时间唤醒系统。

我们将所有与 RTC 驱动程序的通信封装到一个名为`Rtc`的类中。与驱动程序的所有数据交换都通过`/dev/rtc`特殊设备文件进行。在`Rtc`类构造函数中，我们打开设备文件并将结果文件描述符存储在`fd`实例变量中：

```cpp
  fd = open("/dev/rtc", O_RDWR);
```

同样，析构函数用于关闭文件：

```cpp
    ~Rtc() {
      close(fd);
    }
```

由于设备在析构函数中关闭，一旦`Rtc`实例被销毁，我们可以使用**资源获取即初始化**（RAII）习惯用法在出现问题时抛出异常而不泄漏文件描述符：

```cpp
      if (fd < 0) {
        throw std::system_error(errno,
            std::system_category(),
            "Failed to open RTC device");
      }
```

我们的类只定义了一个成员函数—`GetTime`。它是在`RTC_RD_TIME` `ioctl`调用之上的一个包装器。此调用期望返回一个`rtc_time`结构以返回当前时间。它几乎与我们将要用来将 RTC 驱动程序返回的时间转换为 POSIX 时间戳格式的`tm`结构相同，因此我们将它们都放入相同的内存位置作为`union`数据类型：

```cpp
      union {
        struct rtc_time rtc;
        struct tm tm;
      } tm;
```

通过这种方式，我们避免了从一个结构复制相同字段到另一个结构。

数据结构准备就绪后，我们调用`ioctl`调用，将`RTC_RD_TIME`常量作为请求 ID 传递，并将指向我们结构的指针作为存储数据的地址传递：

```cpp
  int ret = ioctl(fd, RTC_RD_TIME, &tm.rtc);
```

成功后，`ioctl`返回`0`。在这种情况下，我们使用`mktime`函数将结果数据结构转换为`time_t` POSIX 时间戳格式：

```cpp
  return mktime(&tm.tm);
```

在`main`函数中，我们创建了`Rtc`类的一个实例，然后调用`GetTime`方法：

```cpp
  Rtc rtc;
  time_t t = rtc.GetTime();
```

自从 POSIX 时间戳表示自 1970 年 1 月 1 日以来的秒数，我们使用`ctime`函数将其转换为人类友好的表示，并将结果输出到控制台：

```cpp
  std::cout << "Current time is " << ctime(&t)
```

当我们运行我们的应用程序时，我们可以看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/b7640217-c2f3-4c53-b5b8-c7901c07760f.png)

我们能够直接从硬件时钟使用`ioctl`读取当前时间。`ioctl` API 在 Linux 嵌入式应用中被广泛使用，用于与设备通信。

# 更多内容

在我们的简单示例中，我们学习了如何只使用一个`ioctl`请求。RTC 设备支持许多其他请求，可用于设置闹钟，更新时间和控制 RTC 中断。更多细节可以在[`linux.die.net/man/4/rtc`](https://linux.die.net/man/4/rtc)的*RTC ioctl 文档*部分找到。

# 使用 libgpiod 控制 GPIO 引脚

在前面的教程中，我们学习了如何使用`ioctl` API 访问 RTC。我们可以使用它来控制 GPIO 引脚吗？答案是肯定的。最近，Linux 添加了一个通用 GPIO 驱动程序，以及一个用户空间库`libgpiod`，通过在通用`ioctl` API 之上添加一个便利层来简化对连接到 GPIO 的设备的访问。此接口允许嵌入式开发人员在任何基于 Linux 的平台上管理其设备，而无需编写设备驱动程序。此外，它提供了 C++的绑定。

结果，尽管仍然被广泛使用，但`wiringPi`库已被弃用，因为其易于使用的接口。

在本教程中，我们将学习如何使用`libgpiod` C++绑定。我们将使用相同的 LED 闪烁示例来查看`wiringPi`和`libgpiod`方法的差异和相似之处。

# 如何做...

我们将创建一个应用程序，使用新的`libgpiod` API 来闪烁连接到树莓派板的 LED。

1.  在您的`~/test`工作目录中，创建一个名为`gpiod`的子目录。

1.  使用您喜欢的文本编辑器在`gpiod`子目录中创建一个`gpiod.cpp`文件。

1.  将应用程序的代码放入`rtc.cpp`文件中：

```cpp
#include <chrono>
#include <iostream>
#include <thread>

#include <gpiod.h>
#include <gpiod.hpp>

using namespace std::literals::chrono_literals;

const int kLedPin = 17;

int main (void)
{

  gpiod::chip chip("gpiochip0");
  auto line = chip.get_line(kLedPin);
  line.request({"test",
                 gpiod::line_request::DIRECTION_OUTPUT, 
                 0}, 0);

  while (true) {
    line.set_value(1);
    std::cout << "ON" << std::endl;
    std::this_thread::sleep_for(500ms);
    line.set_value(0);
    std::cout << "OFF" << std::endl;
    std::this_thread::sleep_for(500ms);
  }

  return 0 ;
}
```

1.  创建一个包含我们程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(gpiod)
add_executable(gpiod gpiod.cpp)
target_link_libraries(gpiod gpiodcxx)
```

1.  使用[Raspberry PI documentation](http://wiringpi.com/examples/blink/)中的*WiringPI 示例*部分的说明，将 LED 连接到您的树莓派板。

1.  建立一个 SSH 连接到您的树莓派板。请按照[Raspberry PI documentation](https://www.raspberrypi.org/documentation/remote-access/)中的说明进行操作。

1.  通过 SSH 将`gpio`文件夹的内容复制到树莓派板上。

1.  安装`libgpiod-dev`软件包：

```cpp
$ sudo apt-get install gpiod-dev
```

1.  通过 SSH 登录到板上，然后构建和运行应用程序：

```cpp
$ cd gpiod && cmake . && make && sudo ./gpiod
```

您的应用程序应该运行，您可以观察 LED 闪烁。

# 它是如何工作的...

我们的应用程序使用了 Linux 中访问 GPIO 设备的新的推荐方式。由于它是最近才添加的，因此需要安装最新版本的 Raspbian 发行版`buster`。

`gpiod`库本身提供了用于使用`ioctl` API 与 GPIO 内核模块通信的高级包装。该接口设计用于 C 语言，其上还有一个用于 C++绑定的附加层。这一层位于`libgpiocxx`库中，它是`libgpiod2`软件包的一部分，与 C 的`libgpiod`库一起提供。

该库使用异常来报告错误，因此代码简单且不会被返回代码检查所淹没。此外，我们不需要担心释放捕获的资源；它会通过 C++ RAII 机制自动完成。

应用程序启动时，它创建了一个 chip 类的实例，该类作为 GPIO 通信的入口点。它的构造函数接受要使用的设备的名称：

```cpp
  gpiod::chip chip("gpiochip0");
```

接下来，我们创建一个 line 的实例，它代表一个特定的 GPIO 引脚：

```cpp
  auto line = chip.get_line(kLedPin);
```

请注意，与`wiringPi`实现不同，我们传递了`17`引脚号，因为`libgpiod`使用本机 Broadcom SOC 通道（**BCM**）引脚编号：

```cpp
const int kLedPin = 17;
```

创建 line 实例后，我们需要配置所需的访问模式。我们构造一个`line_request`结构的实例，传递一个消费者的名称（`"test"`）和一个指示引脚配置为输出的常量：

```cpp
  line.request({"test",
                 gpiod::line_request::DIRECTION_OUTPUT, 
                 0}, 0);
```

之后，我们可以使用`set_value`方法更改引脚状态。与`wiringPi`示例一样，我们将引脚设置为`1`或`HIGH`，持续`500ms`，然后再设置为`0`或`LOW`，再持续`500ms`，循环进行：

```cpp
    line.set_value(1);
    std::cout << "ON" << std::endl;
    std::this_thread::sleep_for(500ms);
    line.set_value(0);
    std::cout << "OFF" << std::endl;
    std::this_thread::sleep_for(500ms);
```

该程序的输出与*通过 GPIO 连接的设备进行控制*配方的输出相同。代码可能看起来更复杂，但新的 API 更通用，可以在任何 Linux 板上工作，而不仅仅是树莓派。

# 还有更多...

有关`libgpiod`和 GPIO 接口的更多信息，可以在[`github.com/brgl/libgpiod`](https://github.com/brgl/libgpiod)找到。

# 控制 I2C 外设设备

通过 GPIO 连接设备有一个缺点。处理器可用于 GPIO 的引脚数量有限且相对较小。当您需要处理大量设备或提供复杂功能的设备时，很容易用完引脚。

解决方案是使用标准串行总线之一连接外围设备。其中之一是**Inter-Integrated Circuit**（**I2C**）。由于其简单性和设备可以仅用两根导线连接到主控制器，因此这被广泛用于连接各种低速设备。

总线在硬件和软件层面都得到了很好的支持。通过使用 I2C 外设，开发人员可以在用户空间应用程序中控制它们，而无需编写复杂的设备驱动程序。

在这个教程中，我们将学习如何在树莓派板上使用 I2C 设备。我们将使用一款流行且便宜的 LCD 显示器。它有 16 个引脚，这使得它直接连接到树莓派板变得困难。然而，通过 I2C 背包，它只需要四根线来连接。

# 操作步骤...

我们将创建一个应用程序，该应用程序在连接到我们的树莓派板的 1602 LCD 显示器上显示文本：

1.  在你的`~/test`工作目录中，创建一个名为`i2c`的子目录。

1.  使用你喜欢的文本编辑器在`i2c`子目录中创建一个`i2c.cpp`文件。

1.  将以下`include`指令和常量定义放入`i2c.cpp`文件中：

```cpp
#include <thread>
#include <system_error>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>

using namespace std::literals::chrono_literals;

enum class Function : uint8_t {
  clear = 0x01,
  home = 0x02,
  entry_mode_set = 0x04,
  display_control = 0x08,
  cursor_shift = 0x10,
  fn_set = 0x20,
  set_ddram_addr = 0x80
};

constexpr int En = 0b00000100;
constexpr int Rs = 0b00000001;

constexpr int kDisplayOn = 0x04;
constexpr int kEntryLeft = 0x02;
constexpr int kTwoLine = 0x08;
constexpr int kBacklightOn = 0x08;
```

1.  现在，我们定义一个新的类`Lcd`，它封装了显示控制逻辑。我们从数据字段和`public`方法开始：

```cpp
class Lcd {
  int fd;

  public:
    Lcd(const char* device, int address) {
      fd = open(device, O_RDWR);
      if (fd < 0) {
        throw std::system_error(errno,
            std::system_category(),
            "Failed to open RTC device");
      }
      if (ioctl(fd, I2C_SLAVE, address) < 0) {
        close(fd);
        throw std::system_error(errno,
            std::system_category(),
            "Failed to aquire bus address");
      }
      Init();
    }

    ~Lcd() {
      close(fd);
    }

    void Clear() {
      Call(Function::clear);
      std::this_thread::sleep_for(2000us);
    }

    void Display(const std::string& text,
                 bool second=false) {
      Call(Function::set_ddram_addr, second ? 0x40 : 0);
      for(char c : text) {
        Write(c, Rs);
      }
    }
```

1.  接下来是`private`方法。低级辅助方法首先出现：

```cpp
private:

    void SendToI2C(uint8_t byte) {
 if (write(fd, &byte, 1) != 1) {
 throw std::system_error(errno,
 std::system_category(),
 "Write to i2c device failed");
 }
    }

    void SendToLcd(uint8_t value) {
      value |= kBacklightOn;
      SendToI2C(value);
      SendToI2C(value | En);
      std::this_thread::sleep_for(1us);
      SendToI2C(value & ~En);
      std::this_thread::sleep_for(50us);
    }

    void Write(uint8_t value, uint8_t mode=0) {
      SendToLcd((value & 0xF0) | mode);
      SendToLcd((value << 4) | mode);
    }
```

1.  一旦辅助函数被定义，我们添加更高级的方法：

```cpp
    void Init() {
      // Switch to 4-bit mode
      for (int i = 0; i < 3; i++) {
        SendToLcd(0x30);
        std::this_thread::sleep_for(4500us);
      }
      SendToLcd(0x20);

      // Set display to two-line, 4 bit, 5x8 character mode
      Call(Function::fn_set, kTwoLine);
      Call(Function::display_control, kDisplayOn);
      Clear();
      Call(Function::entry_mode_set, kEntryLeft);
      Home();
    }

    void Call(Function function, uint8_t value=0) {
      Write((uint8_t)function | value);
    }

    void Home() {
      Call(Function::home);
      std::this_thread::sleep_for(2000us);
    }
};
```

1.  添加使用`Lcd`类的`main`函数：

```cpp
int main (int argc, char* argv[])
{
  Lcd lcd("/dev/i2c-1", 0x27);
  if (argc > 1) {
    lcd.Display(argv[1]);
    if (argc > 2) {
      lcd.Display(argv[2], true);
    }
  }
  return 0 ;
}
```

1.  创建一个包含我们程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(i2c)
add_executable(i2c i2c.cpp)
```

1.  根据这个表格，将你的 1602LCD 显示器的`i2c`背包上的引脚连接到树莓派板上的引脚：

| **树莓派引脚名称** | **物理引脚号** | **1602 I2C 引脚** |
| --- | --- | --- |
| GND | 6 | GND |
| +5v | 2 | VSS |
| SDA.1 | 3 | SDA |
| SCL.1 | 5 | SCL |

1.  建立 SSH 连接到你的树莓派板。按照[Raspberry PI documentation](https://www.raspberrypi.org/documentation/remote-access/ssh/)部分的说明进行操作。

1.  登录到树莓派板并运行`raspi-config`工具以启用`i2c`：

```cpp
sudo raspi-config
```

1.  在菜单中，选择 Interfacing Options | I2C | Yes。

1.  重新启动板以激活新设置。

1.  通过 SSH 将`i2c`文件夹的内容复制到树莓派板上。

1.  通过 SSH 登录到板上，然后构建和运行应用程序：

```cpp
$ cd i2c && cmake . && make && ./i2c Hello, world!
```

你的应用程序应该运行，你可以观察到 LED 在闪烁。

# 工作原理...

在这个教程中，我们的外围设备——LCD 屏幕——通过 I2C 总线连接到板上。这是一种串行接口，所以连接只需要四根物理线。然而，LCD 屏幕可以做的远不止简单的 LED。这意味着用于控制它的通信协议也更复杂。

我们将只使用 1602 LCD 屏幕提供的功能的一小部分。通信逻辑松散地基于 Arduino 的`LiquidCrystal_I2C`库，适用于树莓派。

我们定义了一个`Lcd`类，它隐藏了 I2C 通信的所有复杂性和 1602 控制协议的私有方法。除了构造函数和析构函数之外，它只公开了两个公共方法：`Clear`和`Display`。

在 Linux 中，我们通过设备文件与 I2C 设备通信。要开始使用设备，我们需要使用常规的打开调用打开与 I2C 控制器对应的设备文件：

```cpp
fd = open(device, O_RDWR);
```

可能有多个设备连接到同一总线。我们需要选择要通信的设备。我们使用`ioctl`调用来实现这一点：

```cpp
if (ioctl(fd, I2C_SLAVE, address) < 0) {
```

此时，I2C 通信已配置，我们可以通过向打开的文件描述符写入数据来发出 I2C 命令。然而，这些命令对于每个外围设备都是特定的。因此，在通用 I2C 初始化之后，我们需要继续进行 LCD 初始化。

我们将所有 LCD 特定的初始化放入`Init`私有函数中。它配置操作模式、行数和显示字符的大小。为此，我们定义了辅助方法、数据类型和常量。

基本的辅助函数是`SendToI2C`。它是一个简单的方法，将数据字节写入配置为 I2C 通信的文件描述符，并在出现错误时抛出异常。

```cpp
      if (write(fd, &byte, 1) != 1) {
        throw std::system_error(errno,
            std::system_category(),
            "Write to i2c device failed");
      }
```

除了`SendToI2C`之外，我们还定义了另一个辅助方法`SendToLcd`。它向 I2C 发送一系列字节，形成 LCD 控制器可以解释的命令。这涉及设置不同的标志并处理数据块之间需要的延迟：

```cpp
      SendToI2C(value);
      SendToI2C(value | En);
      std::this_thread::sleep_for(1us);
      SendToI2C(value & ~En);
      std::this_thread::sleep_for(50us);
```

LCD 以 4 位模式工作，这意味着发送到显示器的每个字节都需要两个命令。我们定义`Write`方法来为我们执行这些操作：

```cpp
      SendToLcd((value & 0xF0) | mode);
      SendToLcd((value << 4) | mode);
```

最后，我们定义设备支持的所有可能命令，并将它们放入`Function`枚举类中。`Call`辅助函数可以用于以类型安全的方式调用函数：

```cpp
    void Call(Function function, uint8_t value=0) {
      Write((uint8_t)function | value);
    }
```

最后，我们使用这些辅助函数来定义清除屏幕和显示字符串的公共方法。

由于通信协议的所有复杂性都封装在`Lcd`类中，我们的`main`函数相对简单。

它创建了一个类的实例，传入我们将要使用的设备文件名和设备地址。默认情况下，带有 I2C 背包的 1620 LCD 的地址是`0x27`：

```cpp
  Lcd lcd("/dev/i2c-1", 0x27);
```

`Lcd`类的构造函数执行所有初始化，一旦实例被创建，我们就可以调用`Display`函数。我们不是硬编码要显示的字符串，而是使用用户通过命令行参数传递的数据。第一个参数显示在第一行。如果提供了第二个参数，它也会显示在显示器的第二行：

```cpp
    lcd.Display(argv[1]);
    if (argc > 2) {
      lcd.Display(argv[2], true);
    }
```

我们的程序已经准备好了，我们可以将其复制到树莓派板上并在那里构建。但在运行之前，我们需要将显示器连接到板上并启用 I2C 支持。

我们使用`raspi-config`工具来启用 I2C。我们只需要做一次，但除非之前未启用 I2C，否则需要重新启动：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/6ea36835-ced3-40ef-a8c8-70b0c08c2f71.png)

最后，我们可以运行我们的应用程序。它将在 LCD 显示器上显示以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/91251e94-ad99-47c6-b5c3-e5866ca97b1e.jpg)

现在，我们知道如何从 Linux 用户空间程序控制通过 I2C 总线连接的设备。

# 还有更多...

有关使用 I2C 设备的更多信息，请访问[`elinux.org/Interfacing_with_I2C_Devices`](https://elinux.org/Interfacing_with_I2C_Devices.)上的*与 I2C 设备接口*页面。


# 第十章：降低功耗

嵌入式系统有许多应用需要它们以电池供电。从小型**IoT**（**物联网**的缩写）设备收集传感器数据，将其推送到云端进行处理，到自主车辆和机器人 - 这些系统应尽可能节能，以便它们可以在没有稳定外部电源供应的情况下长时间运行。

功率效率意味着智能控制系统的所有部分的功耗，从外围设备到内存和处理器。功率控制的效率在很大程度上取决于硬件组件的选择和系统设计。如果处理器不支持动态电压控制或外围设备在空闲时无法进入节能模式，那么在软件方面就无法做太多。然而，如果硬件组件实现了标准规范，例如**高级配置和电源接口**（**ACPI**），那么很多功耗管理的负担可以转移到操作系统内核。

在本章中，我们将探索现代硬件平台的不同节能模式以及如何利用它们。我们将学习如何管理外部设备的电源状态，并通过编写更高效的软件来减少处理器的功耗。

我们将涵盖以下主题：

+   在 Linux 中探索节能模式

+   使用**RTC**（**实时时钟**的缩写）唤醒

+   控制 USB 设备的自动挂起

+   配置 CPU 频率

+   使用事件等待

+   使用 PowerTOP 对功耗进行分析

本章的配方将帮助您有效利用现代操作系统的节能功能，并编写针对电池供电设备进行优化的代码。

# 技术要求

要在本章中运行代码示例，您需要具有树莓派 PI 盒子修订版 3 或更高版本。

# 在 Linux 中探索节能模式

当系统处于空闲状态且没有工作要做时，可以将其置于睡眠状态以节省电源。类似于人类的睡眠，它在外部事件唤醒之前无法做任何事情，例如闹钟。

Linux 支持多种睡眠模式。选择睡眠模式和它可以节省的功率取决于硬件支持以及进入该模式和从中唤醒所需的时间。

支持的模式如下：

+   **挂起到空闲**（**S2I**）：这是一种轻度睡眠模式，可以纯粹通过软件实现，不需要硬件支持。设备进入低功耗模式，时间保持暂停，以便处理器在节能空闲状态下花费更多时间。系统通过来自任何外围设备的中断唤醒。

+   **待机**：这类似于 S2I，但通过将所有非引导 CPU 脱机来提供更多的节能。某些设备的中断可以唤醒系统。

+   **挂起到 RAM**（**STR**或**S3**）：系统的所有组件（除了内存），包括 CPU，都进入低功耗模式。系统状态保持在内存中，直到被来自有限设备集的中断唤醒。此模式需要硬件支持。

+   **休眠**或**挂起到磁盘**：这提供了最大的节能，因为所有系统组件都可以关闭电源。进入此状态时，会拍摄内存快照并写入持久存储（磁盘或闪存）。之后，系统可以关闭。作为引导过程的一部分，在唤醒时，恢复保存的快照并系统恢复其工作。

在这个配方中，我们将学习如何查询特定系统支持的睡眠模式以及如何切换到其中之一。

# 如何做...

在这个配方中，我们将使用简单的 bash 命令来访问在**QEMU**（**快速仿真器**的缩写）中运行的 Linux 系统支持的睡眠模式。

1.  按照第三章中描述的步骤运行树莓派 QEMU，*使用不同的架构*。

1.  以用户`pi`登录，使用密码`raspberry`。

1.  运行`sudo`以获取 root 访问权限：

```cpp
$ sudo bash
#
```

1.  要获取支持的睡眠模式列表，请运行以下命令：

```cpp
 # cat /sys/power/state
```

1.  现在切换到其中一个支持的模式：

```cpp
 # echo freeze > /sys/power/state
```

1.  系统进入睡眠状态，但我们没有指示它如何唤醒。现在关闭 QEMU 窗口。

# 工作原理...

电源管理是 Linux 内核的一部分；这就是为什么我们不能使用 Docker 容器来处理它。Docker 虚拟化是轻量级的，并使用主机操作系统的内核。

我们也不能使用真正的树莓派板，因为由于硬件限制，它根本不提供任何睡眠模式。然而，QEMU 提供了完整的虚拟化，包括我们用来模拟树莓派的内核中的电源管理。

Linux 通过 sysfs 接口提供对其电源管理功能的访问。应用程序可以读取和写入`/sys/power`目录中的文本文件。对于 root 用户，对电源管理功能的访问是受限的；这就是为什么我们需要在登录系统后获取 root shell：

```cpp
$ sudo bash
```

现在我们可以获取支持的睡眠模式列表。为此，我们读取`/sys/power/state`文件：

```cpp
$ cat /sys/power/state
```

该文件由一行文本组成。每个单词代表一个支持的睡眠模式，模式之间用空格分隔。我们可以看到 QEMU 内核支持两种模式：`freeze`和`mem`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/e12ba0b1-2558-41d6-83c6-8ad7026751c3.png)

Freeze 代表我们在前一节中讨论的 S2I 状态。`mem`的含义由`/sys/power/mem_sleep`文件的内容定义。在我们的系统中，它只包含`[s2idle]`，代表与`freeze`相同的 S2I 状态。

让我们将我们的模拟器切换到`freeze`模式。我们将单词`freeze`写入`/sys/power/state`，立即 QEMU 窗口变黑并冻结：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/a3f7043f-286b-49d6-acc7-a05c553aa1dd.png)

我们能够让模拟的 Linux 系统进入睡眠状态，但无法唤醒它——没有它能理解的中断源。我们了解了不同的睡眠模式和内核 API 来处理它们。根据嵌入式系统的要求，您可以使用这些模式来降低功耗。

# 还有更多...

有关睡眠模式的更多信息可以在*Linux 内核指南*的相应部分中找到，网址为[`www.kernel.org/doc/html/v4.19/admin-guide/pm/sleep-states.html`](https://www.kernel.org/doc/html/v4.19/admin-guide/pm/sleep-states.html)。

# 使用 RTC 唤醒

在前面的示例中，我们能够让我们的 QEMU 系统进入睡眠状态，但无法唤醒它。我们需要一个设备，当其大部分内部组件关闭电源时，可以向系统发送中断。

**RTC**（**实时时钟**）就是这样的设备之一。它的功能之一是在系统关闭时保持内部时钟运行，并且为此，它有自己的电池。RTC 的功耗类似于电子手表；它使用相同的 3V 电池，并且可以在其自身的电源上工作多年。

RTC 可以作为闹钟工作，在给定时间向 CPU 发送中断。这使得它成为按计划唤醒系统的理想设备。

在这个示例中，我们将学习如何使用内置 RTC 在特定时间唤醒 Linux 系统。

# 如何做...

在这个示例中，我们将提前将系统的唤醒时间设置为 1 分钟，并将系统置于睡眠状态：

1.  登录到任何具有 RTC 时钟的 Linux 系统——任何 Linux 笔记本都可以。不幸的是，树莓派没有内置 RTC，并且没有额外的硬件无法唤醒。

1.  使用`sudo`获取 root 权限：

```cpp
$ sudo bash
#
```

1.  指示 RTC 在`1`分钟后唤醒系统：

```cpp
# date '+%s' -d '+1 minute' > /sys/class/rtc/rtc0/wakealarm
```

1.  将系统置于睡眠状态：

```cpp
# echo freeze > /sys/power/state
```

1.  等待一分钟。您的系统将会唤醒。

# 工作原理...

与 Linux 内核提供的许多其他功能一样，RTC 可以通过 sysfs 接口访问。为了设置一个将向系统发送唤醒中断的闹钟，我们需要向`/sys/class/rtc/rtc0/wakealarm`文件写入一个**POSIX**（**Portable Operating System Interface**的缩写）时间戳。

我们在第十一章中更详细地讨论的 POSIX 时间戳，定义为自纪元以来经过的秒数，即 1970 年 1 月 1 日 00:00。

虽然我们可以编写一个程序，使用`time`函数读取当前时间戳，再加上 60，并将结果写入`wakealarm`文件，但我们可以使用 Unix shell 和`date`命令在一行中完成这个操作，这在任何现代 Unix 系统上都可以实现。

date 实用程序不仅可以使用不同格式格式化当前时间，还可以解释不同格式的日期和时间。

我们指示`date`解释时间字符串`+1 minute`，并使用格式化模式`%s`将其输出为 POSIX 时间戳。我们将其标准输出重定向到`wakealarm`文件，有效地传递给 RTC 驱动程序：

```cpp
date '+%s' -d '+1 minute' > /sys/class/rtc/rtc0/wakealarm
```

现在，知道 60 秒后闹钟会响，我们可以让系统进入睡眠状态。与前一个教程一样，我们将所需的睡眠模式写入`/sys/power/state`文件：

```cpp
# echo freeze > /sys/power/state
```

系统进入睡眠状态。您会注意到屏幕关闭了。如果您使用**Secure Shell**（**SSH**）连接到 Linux 框，命令行会冻结。然而，一分钟后它会醒来，屏幕会亮起，终端会再次响应。

这种技术非常适合定期、不经常地从传感器收集数据，比如每小时或每天。系统大部分时间都处于关闭状态，只有在收集数据并存储或发送到云端时才会唤醒，然后再次进入睡眠状态。

# 还有更多...

设置 RTC 闹钟的另一种方法是使用`rtcwake`实用程序。

# 控制 USB 设备的 autosuspend

关闭外部设备是节省电力的最有效方法之一。然而，并不总是容易理解何时可以安全地关闭设备。外围设备，如网络卡或存储卡，可以执行内部数据处理；否则，在任意时间关闭设备的缓存和电源可能会导致数据丢失。

为了缓解这个问题，许多通过 USB 连接的外部设备在主机请求时可以将自己切换到低功耗模式。这样，它们可以在进入挂起状态之前执行处理内部数据的所有必要步骤。

由于 Linux 只能通过其 API 访问外围设备，它知道设备何时被应用程序和内核服务使用。如果设备在一定时间内没有被使用，Linux 内核中的电源管理系统可以自动指示设备进入省电模式——不需要来自用户空间应用程序的显式请求。这个功能被称为**autosuspend**。然而，内核允许应用程序控制设备的空闲时间，之后 autosuspend 会生效。

在这个教程中，我们将学习如何启用 autosuspend 并修改特定 USB 设备的 autosuspend 间隔。

# 如何做...

我们将启用 autosuspend 并修改连接到 Linux 框的 USB 设备的 autosuspend 时间：

1.  登录到您的 Linux 框（树莓派、Ubuntu 和 Docker 容器不适用）。

1.  切换到 root 账户：

```cpp
$ sudo bash
#
```

1.  获取所有连接的 USB 设备的当前`autosuspend`状态：

```cpp
# for f in /sys/bus/usb/devices/*/power/control; do echo "$f"; cat $f; done
```

1.  为一个设备启用`autosuspend`：

```cpp
# echo auto > /sys/bus/usb/devices/1-1.2/power/control
```

1.  读取设备的`autosuspend`间隔：

```cpp
# cat /sys/bus/usb/devices/1-1.2/power/autosuspend_delay_ms 
```

1.  修改`autosuspend`间隔：

```cpp
# echo 5000 > /sys/bus/usb/devices/1-1.2/power/autosuspend_delay_ms 
```

1.  检查设备的当前电源模式：

```cpp
# cat /sys/bus/usb/devices/1-1.2/power/runtime_status
```

相同的操作可以使用标准文件 API 在 C++中编程。

# 它是如何工作的...

Linux 通过 sysfs 文件系统公开其电源管理 API，这使得可以通过标准文件读写操作读取当前状态并修改任何设备的设置成为可能。因此，我们可以使用支持基本文件操作的任何编程语言来控制 Linux 中的外围设备。

为了简化我们的示例，我们将使用 Unix shell，但在必要时完全相同的逻辑可以用 C++编程。

首先，我们检查所有连接的 USB 设备的`autosuspend`设置。在 Linux 中，每个 USB 设备的参数都作为`/sysfs/bus/usb/devices/`文件夹下的目录公开。每个设备目录又有一组代表设备参数的文件。所有与电源管理相关的参数都分组在`power`子目录中。

要读取`autosuspend`的状态，我们需要读取设备的`power`目录中的`control`文件。使用 Unix shell 通配符替换，我们可以为所有 USB 设备读取此文件：

```cpp
# for f in /sys/bus/usb/devices/*/power/control; do echo "$f"; cat $f; done
```

对于与通配符匹配的每个目录，我们显示控制文件的完整路径及其内容。结果取决于连接的设备，可能如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/ad39f854-2adc-4c82-93d8-22a61a3718a6.png)

报告的状态可能是 autosuspend 或`on`。如果状态报告为 autosuspend，则自动电源管理已启用；否则，设备始终保持开启。

在我们的情况下，设备`usb1`，`1-1.1`和`1-1.2`是开启的。让我们修改`1-1.2`的配置以使用自动挂起。为此，我们只需向相应的`_control_`文件中写入字符串`_auto_`。

```cpp
# echo auto > /sys/bus/usb/devices/1-1.2/power/control
```

再次运行循环读取所有设备的操作显示，`1-1.2`设备现在处于`autosuspend`模式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/a67c2bca-1a51-47ae-a018-07121f050716.png)

它将在何时被挂起？我们可以从`power`子目录中的`autosuspend_delay_ms`文件中读取：

```cpp
# cat /sys/bus/usb/devices/1-1.2/power/autosuspend_delay_ms 
```

它显示设备在空闲`2000`毫秒后将被挂起：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/eca24651-a7e7-4029-9c0c-a9e827d52322.png)

让我们将其更改为`5`秒。我们在`autosuspend_delay_ms`文件中写入`5000`：

```cpp
# echo 5000 > /sys/bus/usb/devices/1-1.2/power/autosuspend_delay_ms 
```

再次读取它显示新值已被接受：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/7b6ee3c8-c017-4d68-9df7-b5343e3bf17d.png)

现在让我们检查设备的当前电源状态。我们可以从`runtime_status`文件中读取它：

```cpp
# cat /sys/bus/usb/devices/1-1.2/power/runtime_status
```

状态报告为`active`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/71e3495c-e054-41b5-bdf4-1265560fe78f.png)

请注意，内核不直接控制设备的电源状态；它只请求它们改变状态。即使请求设备切换到挂起模式，它也可能因为各种原因而拒绝这样做，例如，它可能根本不支持节能模式。

通过 sysfs 接口访问任何设备的电源管理设置是调整运行 Linux OS 的嵌入式系统的功耗的强大方式。

# 还有更多...

没有直接的方法立即关闭 USB 设备；但在许多情况下，可以通过向`autosuspend_delay_ms`文件中写入`0`来实现。内核将零的自动挂起间隔解释为对设备的立即挂起请求。

在 Linux 中，有关 USB 电源管理的更多细节可以在 Linux 内核文档的相应部分中找到，该文档可在[`www.kernel.org/doc/html/v4.13/driver-api/usb/power-management.html`](https://www.kernel.org/doc/html/v4.13/driver-api/usb/power-management.html)上找到。

# 配置 CPU 频率

CPU 频率是系统的重要参数，它决定了系统的性能和功耗。频率越高，CPU 每秒可以执行的指令就越多。但这是有代价的。更高的频率意味着更高的功耗，反过来意味着需要散热更多的热量以避免处理器过热。

现代处理器能够根据负载使用不同的操作频率。对于计算密集型任务，它们使用最大频率以实现最大性能，但当系统大部分空闲时，它们会切换到较低的频率以减少功耗和热量影响。

适当的频率选择由操作系统管理。在这个示例中，我们将学习如何在 Linux 中设置 CPU 频率范围并选择频率管理器，以微调 CPU 频率以满足您的需求。

# 如何做...

我们将使用简单的 shell 命令来调整树莓派盒子上的 CPU 频率参数：

1.  登录到树莓派或另一个非虚拟化的 Linux 系统。

1.  切换到 root 帐户：

```cpp
$ sudo bash
#
```

1.  获取系统中所有 CPU 核心的当前频率：

```cpp
# cat /sys/devices/system/cpu/*/cpufreq/scaling_cur_freq
```

1.  获取 CPU 支持的所有频率：

```cpp
# cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies
```

1.  获取可用的 CPU 频率管理器：

```cpp
# cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors
```

1.  现在让我们检查当前使用的频率管理器是哪个：

```cpp
# cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 
```

1.  将 CPU 的最小频率调整到最高支持的频率：

```cpp
# echo 1200000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq
```

1.  再次显示当前频率以了解效果：

```cpp
# cat /sys/devices/system/cpu/*/cpufreq/scaling_cur_freq
```

1.  将最小频率调整到最低支持的频率：

```cpp
# echo 600000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_fre
```

1.  现在让我们检查 CPU 频率如何取决于所使用的管理器。选择`performance`管理器并获取当前频率：

```cpp
# echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
# cat /sys/devices/system/cpu/*/cpufreq/scaling_cur_freq
```

1.  选择`powersave`管理器并观察结果：

```cpp
# echo powersave > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
# cat /sys/devices/system/cpu/*/cpufreq/scaling_cur_freq
```

您可以使用常规文件 API 在 C++中实现相同的逻辑。

# 它是如何工作的...

与 USB 电源管理类似，CPU 频率管理系统 API 通过 sysfs 公开。我们可以像常规文本文件一样读取和修改其参数。

我们可以在`/sys/devices/system/cpu/`目录下找到与 CPU 核心相关的所有设置。配置参数按 CPU 核心分组在名为每个代码索引的子目录中，如`cpu1`，`cpu2`等。

我们对与 CPU 频率管理相关的几个参数感兴趣，这些参数位于每个核心的`cpufreq`子目录中。让我们读取所有可用核心的当前频率：

```cpp
# cat /sys/devices/system/cpu/*/cpufreq/scaling_cur_freq
```

我们可以看到所有核心的频率都是相同的，为 600 MHz（`cpufreq`子系统使用 KHz 作为频率的测量单位）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/6d9f305d-d3ca-47eb-8766-1b3fa5718836.png)

接下来，我们弄清楚 CPU 支持的所有频率：

```cpp
# cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies
```

树莓派 3 的 ARM 处理器仅支持两种频率，600 MHz 和 1.2 GHz：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/dd10cdcb-aff0-4f3d-9b17-7416aac38365.png)

我们无法直接设置所需的频率。Linux 通过所谓的**管理器**内部管理 CPU 频率，并且只允许我们调整两个参数：

+   管理器的频率范围

+   管理器的类型

尽管这看起来像是一个限制，但这两个参数足够灵活，可以实现相当复杂的策略。让我们看看如何修改这两个参数如何影响 CPU 频率。

首先，让我们弄清楚支持哪些管理器以及当前使用的是哪个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/52365c50-07d0-495b-942b-f45dc54dd619.png)

当前的管理器是`ondemand`。*它根据系统负载调整频率。目前，树莓派板卡相当空闲，因此使用最低频率 600 MHz。但是如果我们将最低频率设置为最高频率呢？

```cpp
# echo 1200000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq
```

在我们更新了一个核心的`scaling_min_freq`参数后，所有核心的频率都被更改为最大值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/ac1af6c9-2bce-4cfa-a881-8d99f9e5ebad.png)

由于四个核心都属于同一个 CPU，我们无法独立地改变它们的频率；改变一个核心的频率会影响所有核心。但是，我们可以独立地控制不同 CPU 的频率。

现在我们将最小频率恢复到 600 MHz 并更改管理器。我们选择了`performance`管理器，而不是调整频率的`ondemand`管理器，旨在无条件地提供最大性能：

```cpp
echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_g;overnor
```

毫不奇怪，它将频率提高到最大支持的频率：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/ac5ded8a-1be2-402d-9f5c-b475828d8ba9.png)

另一方面，`powersave`调度程序旨在尽可能节省电量，因为它始终坚持使用最低支持的频率，而不考虑负载：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/fc0f3d39-c055-4afe-b659-df0401954695.png)

正如您所看到的，调整频率范围和频率调度程序可以灵活地调整频率，以便根据系统的性质减少 CPU 消耗的电量。

# 还有更多...

除了`ondemand`、`performance`和`powersave`之外，还有其他调度程序可以提供更灵活的 CPU 频率调整，供用户空间应用程序使用。您可以在 Linux CPUFreq 的相应部分中找到有关可用调度程序及其属性的更多详细信息[`www.kernel.org/doc/Documentation/cpu-freq/governors.txt`](https://www.kernel.org/doc/Documentation/cpu-freq/governors.txt)

# 使用事件进行等待

等待是软件开发中极为常见的模式。应用程序必须等待用户输入或数据准备好进行处理。嵌入式程序与外围设备通信，需要知道何时可以从设备读取数据以及设备何时准备好接受数据。

通常，开发人员使用轮询技术的变体进行等待。他们在循环中检查设备特定的可用性标志，当设备将其设置为 true 时，他们继续读取或写入数据。

尽管这种方法易于实现，但从能耗的角度来看效率低下。当处理器不断忙于循环检查标志时，操作系统电源管理器无法将其置于更节能的模式中。根据负载，我们之前讨论的 Linux `ondemand`频率调度程序甚至可以决定增加 CPU 频率，尽管这实际上是一种等待。此外，轮询请求可能会阻止目标设备或设备总线保持在节能模式，直到数据准备就绪。

这就是为什么对于关心能效的轮询程序，它应该依赖于操作系统生成的中断和事件。

在本教程中，我们将学习如何使用操作系统事件来等待特定的 USB 设备连接。

# 如何做...

我们将创建一个应用程序，可以监视 USB 设备并等待特定设备出现：

1.  在您的工作`~/test`目录中创建一个名为`udev`的子目录。

1.  使用您喜欢的文本编辑器在`udev`子目录中创建一个名为`udev.cpp`的文件。

1.  将必要的包含和`namespace`定义放入`udev.cpp`文件中：

```cpp
#include <iostream>
#include <functional>

#include <libudev.h>
#include <poll.h>

namespace usb {
```

1.  现在，让我们定义`Device`类：

```cpp
class Device {
  struct udev_device *dev{0};

  public:
    Device(struct udev_device* dev) : dev(dev) {
    }

    Device(const Device& other) : dev(other.dev) {
      udev_device_ref(dev);
    }

    ~Device() {
        udev_device_unref(dev);
    }

    std::string action() const { 
        return udev_device_get_action(dev);
     }

    std::string attr(const char* name) const {
      const char* val = udev_device_get_sysattr_value(dev,
             name);
      return val ? val : "";
    }
};
```

1.  之后，添加`Monitor`类的定义：

```cpp
class Monitor {
  struct udev_monitor *mon;

  public:
    Monitor() {
      struct udev* udev = udev_new();
      mon = udev_monitor_new_from_netlink(udev, "udev");
      udev_monitor_filter_add_match_subsystem_devtype(
           mon, "usb", NULL);
      udev_monitor_enable_receiving(mon);
    }

    Monitor(const Monitor& other) = delete;

    ~Monitor() {
      udev_monitor_unref(mon);
    }

    Device wait(std::function<bool(const Device&)> process) {
      struct pollfd fds[1];
      fds[0].events = POLLIN;
      fds[0].fd = udev_monitor_get_fd(mon);

      while (true) {
          int ret = poll(fds, 1, -1);
          if (ret < 0) {
            throw std::system_error(errno, 
                std::system_category(),
                "Poll failed");
          }
          if (ret) {
            Device d(udev_monitor_receive_device(mon));
            if (process(d)) {
              return d;
            };
          }
      }
    }
};
};
```

1.  在`usb`命名空间中定义了`Device`和`Monitor`之后，添加一个简单的`main`函数，展示如何使用它们：

```cpp
int main() {
  usb::Monitor mon;
  usb::Device d = mon.wait([](auto& d) {
    auto id = d.attr("idVendor") + ":" + 
              d.attr("idProduct");
    auto produce = d.attr("product");
    std::cout << "Check [" << id << "] action: " 
              << d.action() << std::endl;
    return d.action() == "bind" && 
           id == "8086:0808";
  });
  std::cout << d.attr("product")
            << " connected, uses up to "
            << d.attr("bMaxPower") << std::endl;
  return 0;
}
```

1.  创建一个包含我们程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(udev)
add_executable(usb udev.cpp)
target_link_libraries(usb udev)
```

1.  使用`ssh`将`udev`目录复制到您 Linux 系统上的家目录中。

1.  登录到您的 Linux 系统，将目录切换到`udev`，并使用`cmake`构建程序：

```cpp
$cd ~/udev; cmake. && make
```

现在您可以构建并运行应用程序。

# 它是如何工作的...

为了获取有关 USB 设备事件的系统通知，我们使用了一个名为`libudev`的库。它只提供了一个简单的 C 接口，因此我们创建了简单的 C++包装器来使编码更容易。

对于我们的包装器类，我们声明了一个名为`usb`的`namespace`：

```cpp
namespace usb {
```

它包含两个类。第一个类是`Device`，它为我们提供了一个 C++接口，用于低级`libudev`对象`udev_device`。

我们定义了一个构造函数，从`udev_device`指针创建了一个`Device`实例，并定义了一个析构函数来释放`udev_device`。在内部，`libudev`使用引用计数来管理其对象，因此我们的析构函数调用一个函数来减少`udev_device`的引用计数：

```cpp
    ~Device() {
        udev_device_unref(dev);
    }
    Device(const Device& other) : dev(other.dev) {
      udev_device_ref(dev);
    }
```

这样，我们可以复制`Device`实例而不会出现内存泄漏或文件描述符泄漏。

除了构造函数和析构函数之外，`Device`类只有两个方法：`action`和`attr`。`action`方法返回最近的 USB 设备动作：

```cpp
    std::string action() const { 
        return udev_device_get_action(dev);
     }
```

`attr`方法返回与设备关联的任何 sysfs 属性：

```cpp
    std::string attr(const char* name) const {
      const char* val = udev_device_get_sysattr_value(dev,
             name);
      return val ? val : "";
    }
```

`Monitor`类也有构造函数和析构函数，但我们通过禁用复制构造函数使其不可复制：

```cpp
    Monitor(const Monitor& other) = delete;
```

构造函数使用静态变量初始化`libudev`实例，以确保它只初始化一次：

```cpp
      struct udev* udev = udev_new();
```

它还设置了监视过滤器并启用了监视：

```cpp
      udev_monitor_filter_add_match_subsystem_devtype(
           mon, "usb", NULL);
      udev_monitor_enable_receiving(mon);
```

`wait`方法包含最重要的监视逻辑。它接受类似函数的`process`对象，每次检测到事件时都会调用它：

```cpp
Device wait(std::function<bool(const Device&)> process) {
```

如果事件和它来自的设备是我们需要的，函数应返回`true`；否则，它返回`false`以指示`wait`应继续工作。

在内部，`wait`函数创建一个文件描述符，用于将设备事件传递给程序：

```cpp
      fds[0].fd = udev_monitor_get_fd(mon);
```

然后它设置监视循环。尽管它的名称是`poll`函数，但它并不会不断检查设备的状态；它会等待指定文件描述符上的事件。我们传递`-1`作为超时，表示我们打算永远等待事件：

```cpp
int ret = poll(fds, 1, -1);
```

`poll`函数仅在出现错误或新的 USB 事件时返回。我们通过抛出异常来处理错误情况：

```cpp
          if (ret < 0) {
            throw std::system_error(errno, 
                std::system_category(),
                "Poll failed");
          }
```

对于每个事件，我们创建一个`Device`的新实例，并将其传递给`process`。如果`process`返回`true`，我们退出等待循环，将`Device`的实例返回给调用者：

```cpp
            Device d(udev_monitor_receive_device(mon));
            if (process(d)) {
              return d;
            };
```

让我们看看如何在我们的应用程序中使用这些类。在`main`函数中，我们创建一个`Monitor`实例并调用其`wait`函数。我们使用 lambda 函数来处理每个动作：

```cpp
usb::Device d = mon.wait([](auto& d) {
```

在 lambda 函数中，我们打印有关所有事件的信息：

```cpp
    std::cout << "Check [" << id << "] action: " 
              << d.action() << std::endl;
```

我们还检查特定的动作和设备`id`：

```cpp
    return d.action() == "bind" && 
           id == "8086:0808";
```

一旦找到，我们会显示有关其功能和功率需求的信息：

```cpp
  std::cout << d.attr("product")
            << " connected, uses up to "
            << d.attr("bMaxPower") << std::endl;
```

最初运行此应用程序不会产生任何输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/981bab41-7f4d-4a76-9bd0-5e55b1811789.png)

然而，一旦我们插入 USB 设备（在我这里是 USB 麦克风），我们可以看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/d8c72d62-873a-42ca-9486-e57804844157.png)

应用程序可以等待特定的 USB 设备，并在连接后处理它。它可以在不忙碌循环的情况下完成，依靠操作系统提供的信息。因此，应用程序大部分时间都在睡眠，而`poll`调用被操作系统阻塞。

# 还有更多...

有许多`libudev`的 C++包装器。您可以使用其中之一，或者使用本示例中的代码作为起点创建自己的包装器。

# 使用 PowerTOP 进行功耗分析

在像 Linux 这样运行多个用户空间和内核空间服务并同时控制许多外围设备的复杂操作系统中，要找到可能导致过多功耗的组件并不总是容易的。即使找到了效率低下的问题，修复它可能也很困难。

其中一个解决方案是使用功耗分析工具，如 PowerTOP。它可以诊断 Linux 系统中的功耗问题，并允许用户调整可以节省功耗的系统参数。

在这个示例中，我们将学习如何在树莓派系统上安装和使用 PowerTOP。

# 如何做...

在这个示例中，我们将以交互模式运行 PowerTOP 并分析其输出：

1.  以`pi`用户身份登录到您的树莓派系统，使用密码`raspberry`。

1.  运行`sudo`以获得 root 访问权限：

```cpp
$ sudo bash
#
```

1.  从存储库安装 PowerTOP：

```cpp
 # apt-get install powertop
```

1.  保持在 root shell 中，运行 PowerTOP：

```cpp
 # powertop
```

PowerTOP UI 将显示在您的终端中。使用*Tab*键在其屏幕之间导航。

# 工作原理...

PowerTOP 是由英特尔创建的用于诊断 Linux 系统中功耗问题的工具。它是 Raspbian 发行版的一部分，可以使用`apt-get`命令安装：

```cpp
# apt-get install powertop
```

当我们在没有参数的情况下运行它时，它会以交互模式启动，并按其功耗和它们生成事件的频率对所有进程和内核任务进行排序。正如我们在*使用事件进行等待*一节中讨论的那样，程序需要频繁唤醒处理器，它的能效就越低：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/8f7a54ae-1a79-4f1f-91ce-152fbfd006a0.png)

使用*Tab*键，我们可以切换到其他报告模式。例如，设备统计显示设备消耗了多少能量或 CPU 时间：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/2e968743-e8ab-4fe5-a55b-b05a3742586c.png)

另一个有趣的选项卡是 Tunab。PowerTOP 可以检查影响功耗的一些设置，并标记那些不够理想的设置：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/3140c865-d15a-48e7-80de-28bd1c5857a5.png)

如您所见，两个 USB 设备被标记为`Bad`，因为它们没有使用自动挂起。通过按下*Enter*键，PowerTOP 启用了自动挂起，并显示了一个可以从脚本中使用以使其永久化的命令行。启用自动挂起后，可调状态变为`Good`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/866eb512-32b4-4ea7-a5bd-5f42106a267c.png)

一些系统参数可以调整以节省电力。有时它们是显而易见的，比如在 USB 设备上使用自动挂起。有时它们不是，比如在用于将文件缓存刷新到磁盘的内核上使用超时。使用诊断和优化工具，如 PowerTOP，可以帮助您调整系统以实现最大功耗效率。

# 还有更多...

除了交互模式，PowerTOP 还有其他模式可帮助您优化功耗，如校准、工作负载和自动调整。有关 PowerTOP 功能、使用场景和结果解释的更多信息，请参阅[`01.org/sites/default/files/page/powertop_users_guide_201412.pdf`](https://01.org/sites/default/files/page/powertop_users_guide_201412.pdf)中的*PowerTOP 用户指南*。


# 第十一章：时间点和间隔

嵌入式应用程序处理发生在物理世界中的事件和控制过程——这就是为什么正确处理时间和延迟对它们至关重要。交通灯的切换；声音音调的生成；来自多个传感器的数据同步——所有这些任务都依赖于正确的时间测量。

纯 C 不提供任何标准函数来处理时间。预期应用程序开发人员将使用特定于目标操作系统的时间 API——Windows、Linux 或 macOS。对于裸机嵌入式系统，开发人员必须创建自定义函数来处理时间，这些函数基于特定于目标平台的低级定时器 API。结果，代码很难移植到其他平台。

为了克服可移植性问题，C++（从 C++11 开始）定义了用于处理时间和时间间隔的数据类型和函数。这个 API 被称为`std::chrono`库，它帮助开发人员以统一的方式在任何环境和任何目标平台上处理时间。

在本章中，我们将学习如何在我们的应用程序中处理时间戳、时间间隔和延迟。我们将讨论与时间管理相关的一些常见陷阱，以及它们的适当解决方法。

我们将涵盖以下主题：

+   探索 C++ Chrono 库

+   测量时间间隔

+   处理延迟

+   使用单调时钟

+   使用**可移植操作系统接口**（**POSIX**）时间戳

使用这些示例，您将能够编写可在任何嵌入式平台上运行的时间处理的可移植代码。

# 探索 C++ Chrono 库

从 C++11 开始，C++ Chrono 库提供了标准化的数据类型和函数，用于处理时钟、时间点和时间间隔。在这个示例中，我们将探索 Chrono 库的基本功能，并学习如何处理时间点和间隔。

我们还将学习如何使用 C++字面量来更清晰地表示时间间隔。

# 如何做...

我们将创建一个简单的应用程序，创建三个时间点并将它们相互比较。

1.  在您的`~/test`工作目录中，创建一个名为`chrono`的子目录。

1.  使用您喜欢的文本编辑器在`chrono`子目录中创建一个`chrono.cpp`文件。

1.  将以下代码片段放入文件中：

```cpp
#include <iostream>
#include <chrono>

using namespace std::chrono_literals;

int main() {
  auto a = std::chrono::system_clock::now();
  auto b = a + 1s;
  auto c = a + 200ms;

  std::cout << "a < b ? " << (a < b ? "yes" : "no") << std::endl;
  std::cout << "a < c ? " << (a < c ? "yes" : "no") << std::endl;
  std::cout << "b < c ? " << (b < c ? "yes" : "no") << std::endl;

  return 0;
}
```

1.  创建一个包含程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(chrono)
add_executable(chrono chrono.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++14")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

现在您可以构建和运行应用程序。

# 它是如何工作的...

我们的应用程序创建了三个不同的时间点。第一个是使用系统时钟的`now`函数创建的：

```cpp
auto a = std::chrono::system_clock::now();
```

另外两个时间点是通过添加固定的时间间隔`1`秒和`200`毫秒从第一个时间点派生出来的：

```cpp
auto b = a + 1s;
auto c = a + 200ms;
```

请注意我们是如何在数字值旁边指定时间单位的。我们使用了一个叫做 C++字面量的特性。Chrono 库为基本时间单位定义了这样的字面量。为了使用这些定义，我们添加了以下内容：

```cpp
using namespace std::chrono_literals;
```

这是在我们的`main`函数之前添加的。

接下来，我们将比较这些时间点：

```cpp
std::cout << "a < b ? " << (a < b ? "yes" : "no") << std::endl;
std::cout << "a < c ? " << (a < c ? "yes" : "no") << std::endl;
std::cout << "b < c ? " << (b < c ? "yes" : "no") << std::endl;
```

当我们运行应用程序时，我们会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/00856d97-097c-4ff9-98ef-4ed42bfda18c.png)

如预期的那样，时间点`a`比`b`和`c`都要早，其中时间点`c`（即`a`+200 毫秒）比`b`（`a`+1 秒）要早。字符串字面量有助于编写更易读的代码，C++ Chrono 提供了丰富的函数集来处理时间。我们将在下一个示例中学习如何使用它们。

# 还有更多...

Chrono 库中定义的所有数据类型、模板和函数的信息可以在 Chrono 参考中找到[`en.cppreference.com/w/cpp/chrono `](https://en.cppreference.com/w/cpp/chrono)

# 测量时间间隔

与外围硬件交互或响应外部事件的每个嵌入式应用程序都必须处理超时和反应时间。为了正确地做到这一点，开发人员需要能够以足够的精度测量时间间隔。

C++ Chrono 库提供了一个用于处理任意跨度和精度的持续时间的`std::chrono::duration`模板类。在这个示例中，我们将学习如何使用这个类来测量两个时间戳之间的时间间隔，并将其与参考持续时间进行比较。

# 如何做...

我们的应用程序将测量简单控制台输出的持续时间，并将其与循环中的先前值进行比较。

1.  在您的`〜/test`工作目录中，创建一个名为`intervals`的子目录。

1.  使用您喜欢的文本编辑器在`intervals`子目录中创建一个名为`intervals.cpp`的文件。

1.  将以下代码片段复制到`intervals.cpp`文件中：

```cpp
#include <iostream>
#include <chrono>

int main() {
  std::chrono::duration<double, std::micro> prev;
  for (int i = 0; i < 10; i++) {
    auto start = std::chrono::steady_clock::now();
    std::cout << i << ": ";
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> delta = end - start;
    std::cout << "output duration is " << delta.count() <<" us";
    if (i) {
      auto diff = (delta - prev).count();
      if (diff >= 0) {
        std::cout << ", " << diff << " us slower";
      } else {
        std::cout << ", " << -diff << " us faster";
      }
    }
    std::cout << std::endl;
    prev = delta;
  }
  return 0;
}
```

1.  最后，创建一个`CMakeLists.txt`文件，其中包含我们程序的构建规则：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(interval)
add_executable(interval interval.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++11")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

现在，您可以构建并运行应用程序。

# 它是如何工作的...

在应用程序循环的每次迭代中，我们测量一个输出操作的性能。为此，我们在操作之前捕获一个时间戳，操作完成后捕获另一个时间戳：

```cpp
 auto start = std::chrono::steady_clock::now();
    std::cout << i << ": ";
 auto end = std::chrono::steady_clock::now();
```

我们使用 C++11 的`auto`让编译器推断时间戳的数据类型。现在，我们需要计算这些时间戳之间的时间间隔。从一个时间戳减去另一个时间戳就可以完成任务。我们明确将结果变量定义为`std::chrono::duration`类，该类跟踪`double`值中的微秒：

```cpp
 std::chrono::duration<double, std::micro> delta = end - start;
```

我们使用另一个相同类型的`duration`变量来保存先前的值。除了第一次迭代之外的每次迭代，我们计算这两个持续时间之间的差异：

```cpp
    auto diff = (delta - prev).count();
```

在每次迭代中，持续时间和差异都会打印到终端上。当我们运行应用程序时，我们会得到这个输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/ec323f6d-4496-4050-a609-dc90436a90c5.png)

正如我们所看到的，现代 C++提供了方便的方法来处理应用程序中的时间间隔。由于重载运算符，很容易获得两个时间点之间的持续时间，并且可以添加、减去或比较持续时间。

# 还有更多...

从 C++20 开始，Chrono 库支持直接将持续时间写入输出流并从输入流中解析持续时间。无需将持续时间显式序列化为整数或浮点值。这使得处理持续时间对于 C++开发人员更加方便。

# 处理延迟

周期性数据处理是许多嵌入式应用程序中的常见模式。代码不需要一直运行。如果我们预先知道何时需要处理，应用程序或工作线程可以大部分时间处于非活动状态，只有在需要时才唤醒并处理数据。这样可以节省电力消耗，或者在应用程序空闲时让设备上运行的其他应用程序使用 CPU 资源。

有几种组织周期性处理的技术。运行一个带有延迟的循环的工作线程是其中最简单和最常见的技术之一。

C++提供了标准函数来向当前执行线程添加延迟。在这个示例中，我们将学习两种向应用程序添加延迟的方法，并讨论它们的优缺点。

# 如何做...

我们将创建一个具有两个处理循环的应用程序。这些循环使用不同的函数来暂停当前线程的执行。

1.  在您的`〜/test`工作目录中，创建一个名为`delays`的子目录。

1.  使用您喜欢的文本编辑器在`delays`子目录中创建一个名为`delays.cpp`的文件。

1.  让我们首先添加一个名为`sleep_for`的函数，以及必要的包含：

```cpp
#include <iostream>
#include <chrono>
#include <thread>

using namespace std::chrono_literals;

void sleep_for(int count, auto delay) {
  for (int i = 0; i < count; i++) {
    auto start = std::chrono::system_clock::now();
    std::this_thread::sleep_for(delay);
    auto end = std::chrono::system_clock::now();
    std::chrono::duration<double, std::milli> delta = end - start;
    std::cout << "Sleep for: " << delta.count() << std::endl;
  }
}
```

1.  它后面是第二个函数`sleep_until`：

```cpp
void sleep_until(int count, 
                 std::chrono::milliseconds delay) {
  auto wake_up = std::chrono::system_clock::now();
  for (int i = 0; i < 10; i++) {
    wake_up += delay;
    auto start = std::chrono::system_clock::now();
    std::this_thread::sleep_until(wake_up);
    auto end = std::chrono::system_clock::now();
    std::chrono::duration<double, std::milli> delta = end - start;
    std::cout << "Sleep until: " << delta.count() << std::endl;
  }
}
```

1.  接下来，添加一个简单的`main`函数来调用它们：

```cpp
int main() {
  sleep_for(10, 100ms);
  sleep_until(10, 100ms);
  return 0;
}
```

1.  最后，创建一个`CMakeLists.txt`文件，其中包含我们程序的构建规则：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(delays)
add_executable(delays delays.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++14")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

现在，您可以构建并运行应用程序了。

# 它是如何工作的...

在我们的应用程序中，我们创建了两个函数，`sleep_for`和`sleep_until`。它们几乎相同，只是`sleep_for`使用`std::this_thread::sleep_for`来添加延迟，而`sleep_until`使用`std::this_thread::sleep_until`。

让我们更仔细地看看`sleep_for`函数。它接受两个参数——`count`和`delay`。第一个参数定义了循环中的迭代次数，第二个参数指定了延迟。我们使用`auto`作为`delay`参数的数据类型，让 C++为我们推断实际的数据类型。

函数体由一个循环组成：

```cpp
  for (int i = 0; i < count; i++) {
```

在每次迭代中，我们运行`delay`并通过在`delay`之前和之后获取时间戳来测量其实际持续时间。`std::this_thread::sleep_for`函数接受时间间隔作为参数：

```cpp
    auto start = std::chrono::system_clock::now();
    std::this_thread::sleep_for(delay);
    auto end = std::chrono::system_clock::now();
```

实际延迟以毫秒为单位测量，我们使用`double`值作为毫秒计数器：

```cpp
std::chrono::duration<double, std::milli> delta = end - start;
```

`wait_until`函数只是稍有不同。它使用`std::current_thred::wait_until`函数，该函数接受一个时间点来唤醒，而不是一个时间间隔。我们引入了一个额外的`wake_up`变量来跟踪唤醒时间点：

```cpp
auto wake_up = std::chrono::system_clock::now();
```

最初，它被设置为当前时间，并在每次迭代中，将作为函数参数传递的延迟添加到其值中：

```cpp
wake_up += delay;
```

函数的其余部分与`sleep_for`实现相同，除了`delay`函数：

```cpp
std::this_thread::sleep_until(wake_up);
```

我们运行两个函数，使用相同数量的迭代和相同的延迟。请注意我们如何使用 C++字符串字面量将毫秒传递给函数，以使代码更易读。为了使用字符串字面量，我们添加了以下内容：

```cpp
sleep_for(10, 100ms);
sleep_until(10, 100ms);
```

这是在函数定义之上完成的，就像这样：

```cpp
using namespace std::chrono_literals;
```

不同的延迟函数会有什么不同吗？毕竟，我们在两种实现中都使用了相同的延迟。让我们运行代码并比较结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/f3b5c599-d2cd-4f38-9cdc-a5a908f9ce68.png)

有趣的是，我们可以看到`sleep_for`的所有实际延迟都大于`100`毫秒，而`sleep_until`的一些结果低于这个值。我们的第一个函数`delay_for`没有考虑打印数据到控制台所需的时间。当您确切地知道需要等待多长时间时，`sleep_for`是一个不错的选择。然而，如果您的目标是以特定的周期性唤醒，`sleep_until`可能是一个更好的选择。

# 还有更多...

`sleep_for`和`sleep_until`之间还有其他微妙的差异。系统定时器通常不太精确，并且可能会被时间同步服务（如**网络时间协议** **守护程序**（**ntpd**））调整。这些时钟调整不会影响`sleep_for`，但会影响`sleep_until`。如果您的应用程序依赖于特定时间而不是时间间隔，请使用它；例如，如果您需要每秒重新绘制时钟显示上的数字。

# 使用单调时钟

C++ Chrono 库提供了三种类型的时钟：

+   系统时钟

+   稳定时钟

+   高分辨率时钟

高分辨率时钟通常被实现为系统时钟或稳定时钟的别名。然而，系统时钟和稳定时钟是非常不同的。

系统时钟反映系统时间，因此不是单调的。它可以随时通过时间同步服务（如**网络时间协议**（**NTP**））进行调整，因此甚至可以倒退。

这使得系统时钟成为处理精确持续时间的不良选择。稳定时钟是单调的；它永远不会被调整，也永远不会倒退。这个属性有它的代价——它与挂钟时间无关，通常表示自上次重启以来的时间。

稳定时钟不应该用于需要在重启后保持有效的持久时间戳，例如序列化到文件或保存到数据库。此外，稳定时钟不应该用于涉及来自不同来源的时间的任何时间计算，例如远程系统或外围设备。

在这个示例中，我们将学习如何使用稳定时钟来实现一个简单的软件看门狗。在运行后台工作线程时，重要的是要知道它是否正常工作或因编码错误或无响应的外围设备而挂起。线程定期更新时间戳，而监视例程则将时间戳与当前时间进行比较，如果超过阈值，则执行某种恢复操作。

# 如何做...

在我们的应用程序中，我们将创建一个在后台运行的简单迭代函数，以及在主线程中运行的监视循环。

1.  在您的`~/test`工作目录中，创建一个名为`monotonic`的子目录。

1.  使用您喜欢的文本编辑器在`monotonic`子目录中创建一个`monotonic.cpp`文件。

1.  让我们添加头文件并定义我们例程中使用的全局变量：

```cpp
#include <iostream>
#include <chrono>
#include <atomic>
#include <mutex>
#include <thread>

auto touched = std::chrono::steady_clock::now();
std::mutex m;
std::atomic_bool ready{ false };
```

1.  它们后面是后台工作线程例程的代码：

```cpp
void Worker() {
  for (int i = 0; i < 10; i++) {
    std::this_thread::sleep_for(
         std::chrono::milliseconds(100 + (i % 4) * 10));
    std::cout << "Step " << i << std::endl;
    {
      std::lock_guard<std::mutex> l(m);
      touched = std::chrono::steady_clock::now();
    }
  }
  ready = true;
}
```

1.  添加包含监视例程的`main`函数：

```cpp
int main() {
  std::thread t(Worker);
  std::chrono::milliseconds threshold(120);
  while(!ready) {
    auto now = std::chrono::steady_clock::now();
    std::chrono::milliseconds delta;
    {
      std::lock_guard<std::mutex> l(m);
      auto delta = now - touched;
      if (delta > threshold) {
        std::cout << "Execution threshold exceeded" << std::endl;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

  }
  t.join();
  return 0;
}
```

1.  最后，创建一个包含程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(monotonic)
add_executable(monotonic monotonic.cpp)
target_link_libraries(monotonic pthread)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++11")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)

```

现在可以构建和运行应用程序了。

# 它是如何工作的...

我们的应用程序是多线程的——它由运行监视的主线程和后台工作线程组成。我们使用三个全局变量进行同步。

`touched`变量保存了由`Worker`线程定期更新的时间戳。由于时间戳被两个线程访问，需要进行保护。我们使用一个`m`互斥锁来实现。最后，为了指示工作线程已经完成了它的工作，使用了一个原子变量`ready`。

工作线程是一个包含人为延迟的循环。延迟是基于步骤编号计算的，导致延迟从 100 毫秒到 130 毫秒不等：

```cpp
std::this_thread::sleep_for(
         std::chrono::milliseconds(100 + (i % 4) * 10));
```

在每次迭代中，`Worker`线程更新时间戳。使用锁保护同步访问时间戳：

```cpp
    {
      std::lock_guard<std::mutex> l(m);
      touched = std::chrono::steady_clock::now();
    }
```

监视例程在`Worker`线程运行时循环运行。在每次迭代中，它计算当前时间和上次更新之间的时间间隔：

```cpp
      std::lock_guard<std::mutex> l(m);
      auto delta = now - touched;
```

如果超过阈值，函数会打印警告消息，如下所示：

```cpp
      if (delta > threshold) {
        std::cout << "Execution threshold exceeded" << std::endl;
      }
```

在许多情况下，应用程序可能调用恢复函数来重置外围设备或重新启动线程。我们在监视循环中添加了`10`毫秒的延迟：

```cpp
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
```

这有助于减少资源消耗，同时实现可接受的反应时间。运行应用程序会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/7962b124-e6ed-45a4-b2da-ffa84adf2d9b.png)

我们可以在输出中看到几个警告，表明`worker`线程中的一些迭代所花费的时间超过了`120`毫秒的阈值。这是可以预料的，因为`worker`函数是这样编写的。重要的是我们用一个单调的`std::chrono::steady_clock`函数进行监视。使用系统时钟可能会导致在时钟调整期间对恢复函数的虚假调用。

# 还有更多...

C++20 定义了几种其他类型的时钟，比如`gps_clock`，表示**全球定位系统**（**GPS**）时间，或者`file_clock`，用于处理文件时间戳。这些时钟可能是稳定的，也可能不是。使用`is_steady`成员函数来检查时钟是否是单调的。

# 使用 POSIX 时间戳

POSIX 时间戳是 Unix 操作系统中时间的传统内部表示。POSIX 时间戳被定义为自纪元以来的秒数，即**协调世界时**（**UTC**）1970 年 1 月 1 日的 00:00:00。

由于其简单性，这种表示在网络协议、文件元数据或序列化中被广泛使用。

在这个示例中，我们将学习如何将 C++时间点转换为 POSIX 时间戳，并从 POSIX 时间戳创建 C++时间点。

# 如何做...

我们将创建一个应用程序，将时间点转换为 POSIX 时间戳，然后从该时间戳中恢复时间点。

1.  在你的`~/test`工作目录中，创建一个名为`timestamps`的子目录。

1.  使用你喜欢的文本编辑器在`timestamps`子目录中创建一个名为`timestamps.cpp`的文件。

1.  将以下代码片段放入文件中：

```cpp
#include <iostream>
#include <chrono>

int main() {
  auto now = std::chrono::system_clock::now();

  std::time_t ts = std::chrono::system_clock::to_time_t(now);
  std::cout << "POSIX timestamp: " << ts << std::endl;

  auto restored = std::chrono::system_clock::from_time_t(ts);

  std::chrono::duration<double, std::milli> delta = now - restored;
  std::cout << "Recovered time delta " << delta.count() << std::endl;
  return 0;
}
```

1.  创建一个包含我们程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(timestamps)
add_executable(timestamps timestamps.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++11")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

现在，你可以构建并运行应用程序。

# 它是如何工作的...

首先，我们使用系统时钟为当前时间创建一个时间点对象：

```cpp
auto now = std::chrono::system_clock::now();
```

由于 POSIX 时间戳表示自纪元以来的时间，我们不能使用稳定时钟。然而，系统时钟知道如何将其内部表示转换为 POSIX 格式。它提供了一个`to_time_t`静态函数来实现这个目的：

```cpp
std::time_t ts = std::chrono::system_clock::to_time_t(now);
```

结果被定义为具有类型`std::time_t`，但这是一个整数类型，而不是对象。与时间点实例不同，我们可以直接将其写入输出流：

```cpp
std::cout << "POSIX timestamp: " << ts << std::endl;
```

让我们尝试从这个整数时间戳中恢复一个时间点。我们使用一个`from_time_t`静态函数：

```cpp
auto restored = std::chrono::system_clock::from_time_t(ts);
```

现在，我们有两个时间戳。它们是相同的吗？让我们计算并显示差异：

```cpp
std::chrono::duration<double, std::milli> delta = now - restored;
std::cout << "Recovered time delta " << delta.count() << std::endl;
```

当我们运行应用程序时，我们会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/1b9142d4-dd21-4eed-a8f0-d2457fd084f2.png)

时间戳是不同的，但差异始终小于 1,000。由于 POSIX 时间戳被定义为自纪元以来的秒数，我们丢失了毫秒和微秒等细粒度时间。

尽管存在这样的限制，POSIX 时间戳仍然是时间的重要和广泛使用的传输表示，我们学会了如何在需要时将它们转换为内部 C++表示。

# 还有更多...

在许多情况下，直接使用 POSIX 时间戳就足够了。由于它们被表示为数字，可以使用简单的数字比较来决定哪个时间戳更新或更旧。类似地，从一个时间戳中减去另一个时间戳会给出它们之间的秒数时间间隔。如果性能是一个瓶颈，这种方法可能比与本机 C++时间点进行比较更可取。
