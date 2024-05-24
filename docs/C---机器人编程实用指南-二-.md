# C++ 机器人编程实用指南（二）

> 原文：[`zh.annas-archive.org/md5/E72C92D0A964D187E23464F49CAD88BE`](https://zh.annas-archive.org/md5/E72C92D0A964D187E23464F49CAD88BE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用笔记本电脑控制机器人

使用计算机控制机器人是一件迷人的事情。计算机成为遥控器，机器人根据键盘提供的命令移动。在本章中，我们将介绍使用笔记本电脑无线控制机器人的两种技术。

我们将涵盖以下主题：

+   安装`ncurses`库

+   使用`ncurses`控制 LED 和蜂鸣器

+   使用笔记本电脑键盘控制一辆漫游车（RPi 机器人）

+   安装和设置 QT5

+   使用 GUI 按钮控制 LED

+   使用 QT5 在笔记本电脑上控制漫游车

# 技术要求

您需要此项目的主要硬件组件如下：

+   两个 LED

+   一个蜂鸣器

+   一个 RPi 机器人

本章的代码文件可以从[`github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter05`](https://github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter05)下载。

# 安装`ncurses`库

**New curses**（**ncurses**）是一个编程库，允许开发人员创建基于文本的用户界面。它通常用于创建基于 GUI 的应用程序或软件。`ncurses`库的一个关键特性是我们可以用它来从键盘键获取输入，并在输出端控制硬件设备。我们将使用`ncurses`库编写程序来检测键以相应地控制我们的机器人。例如，如果我们按上箭头，我们希望我们的机器人向前移动。如果我们按左箭头，我们希望我们的机器人向左转。

要安装`ncurses`库，我们首先必须打开命令窗口。要安装`ncurses`，请输入以下命令并按*Enter*：

```cpp
sudo apt-get install libncurses5-dev libncursesw5-dev 
```

接下来，您将被问及是否要安装该库。输入*Y*（表示是）并按*Enter*。`ncurses`库将需要大约三到五分钟的时间下载并安装到您的 RPi 中。

确保您的 RPi 靠近 Wi-Fi 路由器，以便库文件可以快速下载。

# ncurses 函数

安装`ncurses`库后，让我们探索一些属于该库的重要函数：

+   `initscr()`: `initscr()`函数初始化屏幕。它设置内存，并清除命令窗口屏幕。

+   `refresh()`: 刷新函数刷新屏幕。

+   `getch()`: 此函数将检测用户的触摸，并返回该特定键的 ASCII 编号。然后将 ASCII 编号存储在整数变量中，以供后续比较使用。

+   `printw()`: 此函数用于在命令窗口中打印字符串值。

+   `keypad()`: 如果键盘函数设置为 true，则我们还可以从功能键和箭头键中获取用户的输入。

+   `break`: 如果程序在循环中运行，则使用此函数退出程序。

+   `endwin()`: `endwin()`函数释放内存，并结束`ncurses`。

整个`ncurses`程序必须在`initscr()`和`endwin()`函数之间编写：

```cpp
#include <ncurses.h>
...
int main()
{
...
initscr();
...
...
endwin();
return 0;
}
```

# 使用`ncurses`编写 HelloWorld 程序

现在让我们编写一个简单的`ncurses`程序来打印`Hello World`。我将这个程序命名为`HelloWorld.cpp`。`HelloWorld.cpp`程序可以从 GitHub 存储库的`Chapter05`文件夹中下载：

```cpp
#include <ncurses.h>
#include <stdio.h>

int main()
{
initscr(); //initializes and clear the screen
int keypressed = getch(); 
if(keypressed == 'h' || keypressed == 'H')
{
printw("Hello World"); //will print Hello World message
}
getch();
refresh(); 

endwin(); // frees up memory and ends ncurses
return 0;
}
```

使用`ncurses`库编译和运行 C++程序的程序与其他程序不同。首先，我们需要理解程序。之后，我们将学习如何编译和运行它。

在上面的代码片段中，我们首先声明了`ncurses`库和`wiringPi`库。接下来，我们执行以下步骤：

1.  在`main`函数中，我们声明`initscr()`函数来初始化和清除屏幕。

1.  接下来，当用户按下一个键时，将调用`getch`函数，并将该键的 ASCII 数字存储在`keypressed`变量中，该变量是`int`类型。

1.  之后，使用`for`循环，我们检查按下的键是否为`'h'`或(`||`)`'H'`。确保将字母 H 放在单引号中。当我们将字母放在单引号中时，我们会得到该字符的 ASCII 数字。例如，`'h'`返回 ASCII 数字**104**，而`'H'`返回 ASCII 数字**72**。您也可以写入*h*和*H*键按下的 ASCII 数字，分别为 104 和 72。这将如下所示：`if(keypressed == 72 || keypressed == 104)`。数字不应该在引号内。

1.  然后，如果您按下`'h'`或`'H'`键，`Hello World`将在命令窗口内打印出来：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/a4913f2b-b2a2-4fcf-ab0c-8701cebc49c6.png)

1.  如果要在下一行上打印`Hello World`，您可以在`Hello World`文本之前简单地放置`\n`。这将如下所示：`printw("\nHello World")`。

1.  之后，当您按下一个键时，在`if`条件下方的`getch()`函数将被调用，程序将终止。

# 编译和运行程序

要编译和运行`HelloWorld.cpp`程序，请打开终端窗口。在终端窗口内，输入`ls`并按*Enter*。现在您将看到您的 RPi 内所有文件夹名称的列表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/40287ace-cd8f-4e7c-9cfa-89865bee5562.png)

`HelloWorld.cpp`存储在`Cprograms`文件夹中。要打开`Cprograms`文件夹，输入`cd`（更改目录）后跟文件夹名称，然后按*Enter*：

```cpp
cd Cprograms
```

可以看到上一个命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/f826375f-c450-4ede-ac0b-fe923c2b7265.png)

接下来，要查看`Cprograms`文件夹的内容，我们将再次输入`ls`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/4482051d-cae1-4d55-8890-f2aefb226734.png)

在`Cprograms`文件夹中，有一个`Data`文件夹和一些`.cpp`程序。我们感兴趣的程序是`HelloWorld.cpp`程序，因为我们想要编译和构建这个程序。要执行此操作，请输入以下命令并按*Enter*：

```cpp
gcc -o HelloWorld -lncurses HelloWorld.cpp 
```

以下屏幕截图显示编译成功：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/44a8ec5e-8b76-4f6a-bc71-b412c52c47c7.png)

对于任何使用`ncurses`库的代码进行编译，代码如下：

```cpp
gcc -o Programname -lncurses Programname.cpp
```

之后，输入`./HelloWorld`并按*Enter*运行代码：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/9daaa933-e6d0-428d-be62-e2ad58585fec.png)

按下*Enter*后，整个终端窗口将被清除：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/26346c31-ea94-4601-ae18-efe993190bf3.png)

接下来，按下*h*或*H*键，`Hello World`文本将在终端窗口中打印出来。要退出终端窗口，请按任意键：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/28a3046e-ebec-463d-bbb9-1ec982952e54.png)

现在我们已经创建了一个简单的`HelloWorld`程序，并测试了`ncurses`库在终端窗口内的工作，让我们编写一个程序来控制 LED 和蜂鸣器。

# 使用 ncurses 控制 LED 和蜂鸣器

在编译和测试您的第一个`ncurses`程序之后，让我们编写一个程序，通过从键盘提供输入来控制 LED 和蜂鸣器。

# 接线连接

对于这个特定的例子，我们将需要两个 LED 和一个蜂鸣器。LED 和蜂鸣器与 RPi 的接线连接如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2718087d-e112-481b-8b8f-daff5a4c96ea.png)

我们可以从连接图中看到以下内容：

+   第一个 LED 的正极（阳极）引脚连接到 wiringPi 引脚号 15，负极（阴极）引脚连接到物理引脚号 6（地引脚）。

+   第二个 LED 的正极引脚连接到 wiringPi 引脚号 4，负极引脚连接到物理引脚号 14（地引脚）。

+   蜂鸣器的一根引脚连接到 wiringPi 引脚号 27，另一根引脚连接到物理引脚号 34（地引脚）。

# 编写 LEDBuzzer.cpp 程序

我们的程序名为`LEDBuzzer.cpp`。`LEDBuzzer.cpp`程序可以从 GitHub 存储库的`Chapter05`文件夹中下载。`LEDBuzzer`程序如下：

```cpp
#include <ncurses.h>
#include <wiringPi.h>
#include <stdio.h>
int main()
{
 wiringPiSetup();

 pinMode(15,OUTPUT); //LED 1 pin
 pinMode(4, OUTPUT); //LED 2 pin
 pinMode(27,OUTPUT); //Buzzer pin

for(;;){

initscr();

int keypressed = getch();

if(keypressed=='L' || keypressed=='l')
{
 digitalWrite(15,HIGH);
 delay(1000);
 digitalWrite(15,LOW);
 delay(1000);
}

if(keypressed== 69 || keypressed=='e')       // 69 is ASCII number for E.
{
 digitalWrite(4,HIGH);
 delay(1000);
 digitalWrite(4,LOW);
 delay(1000);
}

if(keypressed=='D' || keypressed=='d')
{
 digitalWrite(15,HIGH);
 delay(1000);
 digitalWrite(15,LOW);
 delay(1000);
 digitalWrite(4,HIGH);
 delay(1000);
 digitalWrite(4,LOW);
 delay(1000);
}

if(keypressed=='B' || keypressed== 98)        //98 is ASCII number for b
{
 digitalWrite(27,HIGH);
 delay(1000);
 digitalWrite(27,LOW);
 delay(1000);
 digitalWrite(27,HIGH);
 delay(1000);
 digitalWrite(27,LOW);
 delay(1000);
}

if(keypressed=='x' || keypressed =='X')
{
break; 
}

refresh();
}
endwin(); // 
return 0; 
}
```

编写程序后，让我们看看它是如何工作的：

1.  在上述程序中，我们首先声明了`ncurses`和`wiringPi`库，以及`stdio` C 库

1.  接下来，引脚编号`15`，`4`和`7`被声明为输出引脚

1.  现在，当按下*L*或*l*键时，LED 1 将分别在一秒钟内变为`HIGH`和`LOW`

1.  同样，当按下*E*或*e*键时，LED 2 将分别在一秒钟内变为`HIGH`和`LOW`

1.  如果按下*D*或*d*键，LED 1 将分别在一秒钟内变为`HIGH`和`LOW`，然后 LED 2 将分别在一秒钟内变为`HIGH`和`LOW`

1.  如果按下*b*或*B*键，蜂鸣器将响两次

1.  最后，如果按下*x*或*X*键，C++程序将被终止

在编译代码时，您还必须包括`wiringPi`库的名称，即`lwiringPi`。最终的编译命令如下：

```cpp
gcc -o LEDBuzzer -lncurses -lwiringPi LEDBuzzer.cpp
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/9f9c0804-0e67-4088-a696-2c9deff72ec4.png)

编译代码后，键入`./LEDBuzzer`来运行它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/94b1a78f-987e-495a-a513-ec44922a540a.png)

接下来，按下*L*，*E*，*D*和*B*键，LED 和蜂鸣器将相应地打开和关闭。

# 使用笔记本键盘控制一辆漫游车

在控制 LED 和蜂鸣器之后，让我们编写一个程序，从笔记本控制我们的漫游车（机器人）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/840ae9c4-c3ec-4a37-82b9-34c8a7b78ec7.png)

我保持了与第三章中相同的接线连接，*编程机器人*：

+   wiringPi 引脚编号 0 和 2 连接到电机驱动器的**IN1**和**IN2**引脚

+   wiringPi 引脚编号 3 和 4 连接到**IN3**和**IN4**引脚

+   左电机引脚连接到电机驱动器的**OUT1**和**OUT2**引脚

+   右电机引脚连接到电机驱动器的**OUT3**和**OUT4**引脚

+   树莓派的引脚 6 连接到电机驱动器的地线插座

# 构建一个由笔记本控制的漫游车程序

如果您已经理解了前两个程序，那么现在您可能已经找到了我们笔记本控制的漫游车代码。在这个程序中，我们将使用上、下、左和右箭头键以及*A*、*S*、*X*、*W*和*D*键将机器人向前、向后、向左和向右移动。为了识别来自箭头键的输入，我们需要在程序中包含`keypad()`函数。`Laptop_Controlled_Rover.cpp`程序可以从`GitHub`存储库的`Chapter05`文件夹中下载：

```cpp

int main()
{
...
for(;;)
{
initscr(); 
keypad(stdscr,TRUE);
refresh(); 
int keypressed = getch(); 
if(keypressed==KEY_UP || keypressed == 'W' || keypressed == 'w') 
//KEY_UP command is for UP arrow key
{
printw("FORWARD");
digitalWrite(0,HIGH);
digitalWrite(2,LOW);
digitalWrite(3,HIGH);
digitalWrite(4,LOW);
}
if(keypressed==KEY_DOWN || keypressed == 'X' || keypressed == 'x')
//KEY_DOWN is for DOWN arrow key
{
printw("BACKWARD")
digitalWrite(0,LOW);
digitalWrite(2,HIGH);
digitalWrite(3,LOW);
digitalWrite(4,HIGH);
}

if(keypressed==KEY_LEFT || keypressed == 'A' || keypressed == 'a')
{
//KEY_LEFT is for LEFT arrow key
printw("LEFT TURN");
digitalWrite(0,LOW);
digitalWrite(2,HIGH);
digitalWrite(3,HIGH);
digitalWrite(4,LOW);
}

if(keypressed==KEY_RIGHT || keypressed == 'D' || keypressed == 'd')
{
//KEY_RIGHT is for right arrow keys
printw("RIGHT TURN");
digitalWrite(0,HIGH);
digitalWrite(2,LOW);
digitalWrite(3,LOW);
digitalWrite(4,HIGH);
}

if(keypressed=='S' || keypressed=='s')
{
printw("STOP");
digitalWrite(0,HIGH);
digitalWrite(2,HIGH);
digitalWrite(3,HIGH);
digitalWrite(4,HIGH);
}

if(keypressed=='E' || keypressed=='e')
{
break; 
}
}
endwin(); 
return 0; 
}
```

上述程序可以解释如下：

1.  在上述程序中，如果按下上箭头键，这将被`if`条件内的`KEY_UP`代码识别。如果条件为`TRUE`，机器人将向前移动，并且终端中将打印`FORWARD`。类似地，如果按下*W*或*w*键，机器人也将向前移动。

1.  如果按下下箭头键（`KEY_DOWN`）或*X*或*x*键，机器人将向后移动，并且终端中将打印`BACKWARD`。

1.  如果按下左箭头键（`KEY_LEFT`）或*A*或*a*键，机器人将向左转，终端中将打印`LEFT TURN`。

1.  如果按下右箭头键（`KEY_RIGHT`）或*D*或*d*键，机器人将向右转，终端中将打印`RIGHT TURN`。

1.  最后，如果按下*S*或*s*键，机器人将停止，并且终端中将打印`STOP`。

1.  要终止代码，我们可以按下*E*或*e*键。由于我们没有提供任何时间延迟，机器人将无限期地保持移动，除非您使用*S*或*s*键停止机器人。

在测试代码时，将树莓派连接到移动电源，这样你的机器人就完全无线，可以自由移动。

# 追踪一个正方形路径

在将机器人移动到不同方向后，让我们让机器人追踪一个正方形路径。为此，我们的机器人将按以下方式移动：向前->右转->向前->右转->向前->右转->向前->停止：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/957bbde9-fd66-4935-945e-48cfa850d3a7.png)

在`LaptopControlRover`程序中，我们将创建另一个`if`条件。在这个`if`条件内，我们将编写一个程序来使机器人追踪一个正方形路径。`if`条件将如下所示：

```cpp
if(keypressed == 'r' || keypressed == 'R')
{
forward(); //first forward movement
delay(2000);
rightturn(); //first left turn
delay(500); //delay needs to be such that the robot takes a perfect 90º right turn

forward(); //second forward movement
delay(2000);
rightturn(); //second right turn
delay(500);

forward(); //third forward movement
delay(2000);
rightturn(); //third and last left turn
delay(500);

forward(); //fourth and last forward movement
delay(2000);
stop(); //stop condition
}
```

为了追踪正方形路径，机器人将向前移动四次。它将右转三次，最后停下来。在`main`函数之外，我们需要创建`forward()`，`rightturn()`和`stop()`函数，这样，我们可以简单地调用必要的函数，而不是在主函数中多次编写`digitalWrite`代码。

| **向前条件** | **右转** | **停止** |
| --- | --- | --- |

|

```cpp
void forward()
{
digitalWrite(0,HIGH);
 digitalWrite(2,LOW);
 digitalWrite(3,HIGH);
 digitalWrite(4,LOW);
}
```

|

```cpp
void rightturn()
{
digitalWrite(0,HIGH); 
 digitalWrite(2,LOW); 
 digitalWrite(3,LOW); 
 digitalWrite(4,HIGH);
}
```

|

```cpp
void stop()
{
digitalWrite(0,HIGH); 
 digitalWrite(2,HIGH); 
 digitalWrite(3,HIGH); 
 digitalWrite(4,HIGH);
}
```

|

这是我们如何使用笔记本电脑控制机器人，借助键盘按键的帮助。接下来，让我们看看第二种技术，我们将使用 QT5 创建 GUI 按钮。当按下这些按钮时，机器人将朝不同的方向移动。

# 安装和设置 QT5

QT 是一个跨平台应用程序框架，通常用于嵌入式图形用户界面。QT 的最新版本是 5，因此也被称为 QT5。要在我们的 RPi 内安装 QT5 软件，打开终端窗口并输入以下命令：

```cpp
sudo apt-get install qt5-default
```

上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/ae4420cd-ba5f-4ff8-bf3e-641efe8b43e6.png)

这个命令将下载在后台运行的必要的`qt5`文件。接下来，要下载和安装 QT5 IDE，输入以下命令：

```cpp
sudo apt-get install qtcreator
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/b0bb610a-68fa-40d3-b57f-c34c0a757f8e.png)

QT5 IDE 的安装将需要大约 10 到 15 分钟，具体取决于您的互联网速度。如果在安装 QT5 时遇到任何问题，请尝试更新和升级您的 RPi。要做到这一点，请在终端窗口中输入以下命令：

```cpp
sudo apt-get update
sudo apt-get upgrade -y
```

# 设置 QT5

在 QT5 中编写任何程序之前，我们首先需要设置它，以便它可以运行 C++程序。要打开 QT5，点击树莓图标，转到“编程”，然后选择“Qt Creator”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/65b660f8-1756-4f5d-8626-ce083d488dbb.png)

QT5 在 RPi 上运行速度较慢，因此打开 IDE 需要一些时间。点击工具，然后选择“选项...”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/65e1375e-cead-40ae-83de-b2450a4ad34f.png)

在“选项...”中，点击设备，确保类型设置为桌面。名称应为“本地 PC”，这是指 RPi：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/fef1ed68-6b3a-486e-a335-2d9516ff0eb0.png)

之后，点击“构建和运行”选项。接下来，选择“工具包”选项卡，点击“桌面”（默认）选项：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/02292176-eb69-4d2e-ab2b-9d2d2198a22d.png)

选择“构建和运行”选项后，我们需要进行一些修改：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/13a94678-1c8e-46f0-807c-96777225ad11.png)

让我们逐步看修改：

1.  保持名称为“桌面”。

1.  将文件系统的名称设置为`RPi`。

1.  在设备类型中，选择桌面选项。

1.  系统根（系统根）默认设置为`/home/pi`，这意味着当我们创建新的 QT5 应用程序时，它将被创建在`pi`文件夹内。现在，我们将在`pi`文件夹内创建一个名为`QTPrograms`的新文件夹，而不是在`pi`文件夹中创建我们的 QT 项目。要更改文件夹目录，点击“浏览”按钮。之后，点击文件夹选项。将此文件夹命名为`QTPrograms`，或者您想要的任何其他名称。选择`QTPrograms`文件夹，然后选择“选择”按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/51cac37f-956e-4767-a91a-43c4b4af7c14.png)

1.  接下来，我们必须将编译器设置为 GCC。要做到这一点，点击编译器选项卡。在里面，点击“添加”下拉按钮。转到 GCC 并选择 C++选项：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/dd8bb18d-6801-416c-83b9-8403c1d48d81.png)

现在，在 C++选项下，您将看到 GCC 编译选项：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/f8f1d059-82f7-4c5e-b53a-ea0bb10c1fad.png)

之后，点击 Apply 按钮应用更改，然后点击 OK 按钮。接下来，再次点击 Tools，打开 Options。在 Build and run 选项内，选择 Kits 选项卡，再次选择 Desktop 选项。这次，在 C++选项旁边，您将看到一个下拉选项。点击这个选项，选择 GCC 编译器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/18bf2737-2fa8-42f4-a46f-604d5c0249fc.png)

1.  接下来，检查调试器选项。它应该设置为位于/usr/bin/gdb 的 System GDB。

1.  最后，检查 QT5 版本。目前，我正在使用最新版本的 QT，即 5.7.1。当您阅读到这一章时，最新版本可能已经更新。

进行这些更改后，点击 Apply，然后点击 OK。在设置 QT5 之后，让我们编写我们的第一个程序，使用 GUI 按钮来打开和关闭 LED。

# 使用 GUI 按钮控制 LED

在本节中，我们将创建一个简单的 QT5 程序，通过 GUI 按钮来控制 LED 的开关。对于这个项目，您将需要两个 LED：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/25312b51-bdbe-4aa9-a586-5708f9bfdb24.png)

LED 的接线与`LEDBuzzer`项目中的完全相同：

+   第一个 LED 的阳极（正极）引脚连接到 wiringPi 引脚号 0，阴极（负极）引脚连接到物理引脚号 9（地线引脚）

+   第二个 LED 的阳极引脚连接到 wiringPi 引脚号 2，阴极引脚连接到物理引脚号 14（地线引脚）

# 创建 QT 项目

用于打开和关闭 LED 的 QT5 项目称为`LedOnOff`。您可以从 GitHub 存储库的`Chapter05`文件夹中下载此项目。下载`LedOnOff`项目文件夹后，打开`LedOnOff.pro`文件以在 QT5 IDE 中查看项目。

按照以下步骤在 QT5 IDE 中创建项目：

1.  点击 File 选项，然后点击 New File or Project...：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/d51333f1-b159-4e77-b70a-4f3d9d17a3d8.png)

1.  接下来，选择 QT Widgets Application 选项，然后点击 Choose 按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/64f1c143-97e0-4298-aab6-79708a8d26df.png)

1.  之后，给您的项目命名。我将我的项目命名为`LEDOnOff`。之后，将目录更改为`QTPrograms`，以便在此文件夹中创建项目，然后点击 Next：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/8bd25d15-d135-466f-a2b2-327c457c4c28.png)

1.  保持 Desktop 选项选中，然后点击 Next：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/cbbd4970-98a3-4ab3-9349-f3426ff913d2.png)

1.  现在您应该看到某些文件名，这些是项目的一部分。保持名称不变，然后点击 Next：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/5d820970-15e4-48b1-893c-e14035aa8a87.png)

1.  最后，您将看到一个摘要窗口，其中将显示将要创建的所有文件的摘要。我们不需要在此窗口中进行任何更改，因此点击 Finish 创建项目：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/af895aa2-69a6-4b85-8a0d-bdccc5ea4bc3.png)

在 IDE 的左侧，您将看到设计、C++和头文件。首先，我们将打开`LEDOnOff.pro`文件并添加`wiringPi`库的路径。在文件底部，添加以下代码：

```cpp
LIBS += -L/usr/local/lib -lwiringPi
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/d38aaebe-77ab-4dfd-a396-5587c5f7d909.png)

接下来，打开`Forms`文件夹内的`mainwindow.ui`文件。`mainwindow.ui`文件是设计文件，我们将在其中设计 GUI 按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/8b17f97c-6da1-408f-aee6-dfdbf4aeebcb.png)

`mainwindow.ui`文件将在 Design 选项卡中打开。在 Design 选项卡的左侧是小部件框，其中包含按钮、列表视图和布局等小部件。中间是设计区域，我们将在其中拖动 UI 组件。在右下角，显示所选 UI 组件的属性：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/054b1c4c-0498-4d73-8a89-73e00683ab2b.png)

接下来，要创建 GUI 按钮，将 Push Button 小部件拖到设计区域内。双击按钮，将文本更改为`ON`。之后，选中 Push Button，将 objectName（在属性窗口内）更改为`on`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/c7cf40ee-026a-48fb-8763-eaaeaa566e95.png)

之后，添加两个按钮。将一个按钮的名称设置为`OFF`，**objectName**设置为`off`。将另一个按钮的名称设置为`ON / OFF`，**objectName**设置为`onoff`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/d1127285-7189-4250-908a-20d153280eb3.png)

我们可以使用两种不同类型的按钮函数来打开和关闭 LED：

+   `clicked()`: `clicked`按钮函数将在按钮被点击时立即执行。

+   `pressed()`和`released()`: `pressed`按钮函数会在您按住或按住按钮时一直执行。当我们使用`pressed`函数时，我们还必须使用`released()`函数。释放的函数包含指示按钮释放时应发生的操作的代码。

我们将把`clicked()`函数链接到**ON**和**OFF**按钮，并将`pressed()`和`released()`函数链接到**ON/OFF**按钮。接下来，要将`clicked()`函数链接到**ON**按钮，右键单击**ON**按钮，选择 Go to slot...选项，然后选择`clicked()`函数。然后，按下 OK：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/162e949c-7d25-455a-818b-4bc20b19d29d.png)

现在，一旦您选择`clicked()`函数，`mainwindow.cpp`文件（此文件位于`Sources`文件夹中）中将创建一个名为`on_on_clicked()`（`on_buttonsobjectname_clicked`）的点击函数。在此函数中，我们将编写打开 LED 的程序。但在此之前，我们需要在`mainwindow.h`文件中声明`wiringPi`库和引脚。此文件位于`Headers`文件夹中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/60c03849-01f6-41e7-b983-65f4226b9434.png)

我们还需要声明`QMainWindow`库，它将创建一个包含我们按钮的窗口。接下来，我已将`led1`引脚设置为引脚`0`，将`led2`引脚设置为引脚`2`。之后，再次打开`mainwindow.cpp`文件。然后我们将执行以下操作：

1.  首先，我们将声明`wiringPiSetup();`函数

1.  接下来，我们将把`led1`和`led2`设置为`OUTPUT`引脚

1.  最后，在`on_on_clicked()`函数中，将`led1`和`led2`引脚设置为`HIGH`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/53314662-d1ee-438e-ab16-19d75179a05c.png)

接下来，要关闭 LED 灯，再次打开`mainwindow.ui`文件，右键单击关闭按钮，选择 Go to slot...，然后再次选择`clicked()`函数。在`mainwindow.cpp`文件中，将创建一个名为`on_off_clicked`的新函数。在此函数中，我们将编写关闭 LED 灯的程序。

要编程 ON/OFF 按钮，右键单击它，选择 Go to slot...，然后选择`pressed()`函数。将在`mainwindow.ui`文件中创建一个名为`on_onoff_pressed()`的新函数。接下来，右键单击**ON/OFF**按钮，选择 Go to slot...，然后选择`released()`函数。现在将创建一个名为`on _onoff_released()`的新函数。

在`on_onoff_pressed()`函数中，我们将编写一个程序来打开 LED 灯。在`on_onoff_released()`函数中，我们将编写一个程序来关闭 LED 灯：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/1bc3b0ab-dfbc-4c41-a198-81693f52be8f.png)

在运行代码之前，单击文件，然后单击全部保存。接下来，要构建和运行代码，请单击构建，然后单击运行选项。MainWindow 出现需要大约 30 到 40 秒，在主窗口中，您将看到以下 GUI 按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/bdea7634-eed9-4dc7-b75c-232e8333e4df.png)

现在，当您点击 ON 按钮时，LED 将打开。当您点击 OFF 按钮时，LED 将关闭。最后，当您按住**ON / OFF**按钮时，LED 将一直打开，直到您松开为止，然后它们将关闭。

# 处理错误

在控制台中，您可能会看到一些次要错误。如果主窗口已打开，您可以忽略这些错误：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/22178e23-8e5a-4181-b245-d89de8d0aeaf.png)

当您打开 Qt Creator IDE 时，GCC 编译器可能会不断重置。因此，在运行项目后，您将收到以下错误：

```cpp
Error while building/deploying project LEDOnOff (kit: Desktop)
 When executing step "qmake"
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2fb0fe4e-152a-48a5-9b8b-65b14442f370.png)

如果您遇到此错误，请转到工具，然后选项，并将 C++编译器设置为 GCC，如“设置 QT5”部分的*步骤 5*中所示。

# 使用 QT5 控制笔记本电脑的小车

现在我们可以控制 LED 灯，让我们看看如何使用 QT5 控制小车。在 Qt Creator IDE 中，创建一个新项目并命名为`QTRover`。您可以从本章的 GitHub 存储库中下载`QTRover`项目文件夹。我们现在可以使用`clicked()`函数和`pressed()`和`released()`函数来创建这个`QTRover`项目。为此，我们有以下选项：

1.  如果我们只使用`clicked()`函数创建这个项目，我们需要创建五个按钮：前进、后退、左转、右转和停止。在这种情况下，我们需要每次按下停止按钮来停止机器人。

1.  如果我们只使用`pressed()`和`released()`函数创建这个项目，我们只需要创建四个按钮：前进、后退、左转和右转。在这种情况下，我们不需要停止按钮，因为当按钮释放时，小车会停止。

1.  或者，我们也可以使用`clicked()`、`pressed()`和`released()`函数的组合，其中前进、后退和停止按钮将链接到`clicked()`函数，左右按钮将链接到`pressed()`和`released()`函数。

在这个项目中，我们将选择第三个选项，即`clicked()`、`pressed()`和`released()`函数的组合。在创建这个项目之前，我们将关闭`LEDOnOff`项目，因为如果`LEDOnOff`和`QTRover`项目都保持打开状态，有可能如果您在一个项目中进行 UI 更改，代码可能会在另一个项目中更改，从而影响到您的两个项目文件。要关闭`LEDOnOff`项目，请右键单击它，然后选择关闭项目`LEDOnOff`选项。

接下来，在`QTRover.pro`文件中添加`wiringPi`库路径：

```cpp
LIBS += -L/usr/local/lib -lwiringPi
```

之后，打开`mainwindow.ui`文件并创建五个按钮。将它们标记为`FORWARD`、`BACKWARD`、`LEFT`、`RIGHT`和`STOP`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/fcbea460-fcd5-467d-afdf-543c8e5ee98e.png)

将按钮对象的名称设置如下：

+   将`FORWARD`按钮对象名称设置为 forward

+   将`BACKWARD`按钮对象名称设置为 backward

+   将`LEFT`按钮对象名称设置为 left

+   将`RIGHT`按钮对象名称设置为 right

+   将`STOP`按钮对象名称设置为 stop

之后，右键单击前进、后退和停止按钮，并将`clicked()`函数添加到这三个按钮。同样，右键单击左和右按钮，并将`pressed()`和`released()`函数添加到这些按钮。

接下来，打开`mainwindow.h`文件并声明`wiringPi`和`QMainWindow`库。还要声明四个`wiringPi`引脚号。在我的情况下，我使用引脚号`0`、`2`、`3`和`4`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/5d9b41e5-a899-4f20-8e6d-9fc90ed55599.png)

在`mainwindow.cpp`文件内，我们将有三个`on_click`函数来向前移动（`on_forward_clicked`）、向后移动（`on_backward_clicked`）和停止（`on_stop_clicked`）。

我们还有两个`on_pressed`和`on_released`函数用于左（`on_left_pressed`和`on_left_released`）和右（`on_right_pressed`和`on_right_released`）按钮。

以下步骤描述了移动机器人在不同方向上所需的步骤：

1.  在`on_forward_clicked()`函数内，我们将编写程序来使机器人向前移动：

```cpp
digitalWrite(leftmotor1, HIGH);
digitalWrite(leftmotor2, LOW);
digitalWrite(rightmotor1, HIGH);
digitalWrite(rightmotor2, LOW);
```

1.  接下来，在`on_backward_clicked()`函数内，我们将编写程序来使机器人向后移动：

```cpp
digitalWrite(leftmotor1, HIGH);
digitalWrite(leftmotor2, LOW);
digitalWrite(rightmotor1, HIGH);
digitalWrite(rightmotor2, LOW);
```

1.  之后，在`on_left_pressed()`函数内，我们将编写程序来进行轴向左转或径向左转：

```cpp
digitalWrite(leftmotor1, LOW);
digitalWrite(leftmotor2, HIGH);
digitalWrite(rightmotor1, HIGH);
digitalWrite(rightmotor2, LOW);
```

1.  然后，在`on_right_pressed()`函数内，我们将编写程序来进行轴向右转或径向右转：

```cpp
digitalWrite(leftmotor1, HIGH);
digitalWrite(leftmotor2, LOW);
digitalWrite(rightmotor1, LOW);
digitalWrite(rightmotor2, HIGH);
```

1.  在`on_stop_clicked()`函数内，我们将编写程序来停止机器人：

```cpp
digitalWrite(leftmotor1, HIGH);
digitalWrite(leftmotor2, HIGH);
digitalWrite(rightmotor1, HIGH);
digitalWrite(rightmotor2, HIGH);
```

完成代码后，保存所有文件。之后，运行程序并测试最终输出。运行代码后，您将看到带有向前、向后、向左、向右和停止按钮的主窗口。按下每个 GUI 按钮以使机器人朝所需方向移动。

# 总结

在本章中，我们看了两种不同的技术来使用笔记本电脑控制机器人。在第一种技术中，我们使用`ncurses`库从键盘接收输入，以相应地移动机器人。在第二种技术中，我们使用 QT Creator IDE 创建 GUI 按钮，然后使用这些按钮来使机器人朝不同方向移动。

在下一章中，我们将在树莓派上安装 OpenCV 软件。之后，我们将使用树莓派摄像头记录图片和视频。

# 问题

1.  `ncurses`程序应该在哪两个函数之间编写？

1.  `initscr()`函数的目的是什么？

1.  如何在终端窗口中编译`ncurses`代码？

1.  我们在 QT Creator 中使用了哪个 C++编译器？

1.  你会使用哪个按钮功能或功能来在按下按钮时使机器人向前移动？


# 第三部分：人脸和物体识别机器人

在本节中，您将使用 OpenCV 来检测人脸和现实世界中的物体。然后，我们将扩展 OpenCV 的功能，以识别不同的人脸，并在检测到正确的人脸时移动机器人。

本节包括以下章节：

+   第六章，*使用 OpenCV 访问 RPi 相机*

+   第七章，*使用 OpenCV 构建一个物体跟随机器人*

+   第八章，*使用 Haar 分类器进行人脸检测和跟踪*


# 第六章：使用 OpenCV 访问 RPi 相机

我们可以使用树莓派连接到外部 USB 网络摄像头或**树莓派相机**（**RPi 相机**）来识别对象和人脸，这是树莓派最令人兴奋的事情之一。

为了处理来自相机的输入，我们将使用 OpenCV 库。由于安装 OpenCV 需要很长时间并涉及多个步骤，本章将专门用于让您开始运行。

在本章中，您将探索以下主题：

+   在树莓派上安装 OpenCV 4.0.0

+   启用并连接 RPi 相机到 RPi

+   使用 RPi 相机捕获图像和视频

+   使用 OpenCV 读取图像

# 技术要求

在本章中，您将需要以下内容：

+   树莓派相机模块-截至 2019 年，最新的 RPi 相机模块称为**RPi 相机 V2 1080P**

+   树莓派相机外壳（安装支架）

本章的代码文件可以从[`github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter06`](https://github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter06)下载。

# 在树莓派上安装 OpenCV 4.0.0

**开源计算机视觉库**（**OpenCV**）是一个开源的计算机视觉和机器学习库。OpenCV 库包括 2500 多个计算机视觉和机器学习算法，可用于识别对象、检测颜色和跟踪现实生活中或视频中的运动物体。OpenCV 支持 C++、Python 和 Java 编程语言，并可以在 Windows、macOS、Android 和 Linux 上运行。

在树莓派上安装 OpenCV 是一个耗时且冗长的过程。除了 OpenCV 库，我们还必须安装多个库和文件，以使其正常工作。安装 OpenCV 的步骤将在我运行 Raspbian Stretch 的树莓派 3B+型号上执行。我们要安装的 OpenCV 版本是 OpenCV 4.0.0。

在安装 OpenCV 时，我们将下载多个文件。如果您住在大房子里，请确保您坐在 Wi-Fi 路由器附近，以便 RPi 接收良好的信号强度。如果 RPi 离 Wi-Fi 很远，下载速度可能会受到影响，安装 OpenCV 可能需要更长的时间。我在我的 RPi 3B+上安装 OpenCV 大约花了 3 个小时，下载速度大约为 500-560 Kbps。

# 卸载 Wolfram 和 LibreOffice

如果您使用 32GB 的 microSD 卡，Raspbian Stretch 将只占用存储空间的 15%，但如果您使用 8GB 的 microSD 卡，它将占用 50%的空间。如果您使用 8GB 的 microSD 卡，您需要释放一些空间。您可以通过卸载一些未使用的应用程序来实现。其中两个应用程序是 Wolfram 引擎和 LibreOffice。

在 Raspbian Stretch 上卸载应用程序很容易。您只需要在终端窗口中输入一个命令。让我们从卸载 Wolfram 引擎开始：

```cpp
sudo apt-get purge wolfram-engine -y
```

接下来，使用相同的命令卸载 LibreOffice：

```cpp
sudo apt-get purge libreoffice* -y
```

卸载两个软件后，我们可以使用两个简单的命令进行清理：

```cpp
sudo apt-get clean
sudo apt-get autoremove -y
```

现在我们已经释放了一些空间，让我们更新 RPi。

# 更新您的 RPi

更新您的 RPi 涉及一些简单的步骤：

1.  打开终端窗口，输入以下命令：

```cpp
sudo apt-get update 
```

1.  通过输入以下命令升级 RPi：

```cpp
sudo apt-get upgrade -y
```

1.  重新启动 RPi：

```cpp
sudo shutdown -r now
```

一旦您的 RPi 重新启动，再次打开终端窗口。

在终端窗口运行某些命令时，您可能会收到提示，询问您是否要继续。在此过程的命令中，我们已经添加了`-y`命令（在行的末尾），它将自动应用**yes**命令到提示。

# 安装 cmake、image、video 和 gtk 软件包

`cmake`是一个配置实用程序。使用`cmake`，我们可以在安装后配置不同的 OpenCV 和 Python 模块。要安装`cmake`软件包，请输入以下命令：

```cpp
sudo apt-get install build-essential cmake pkg-config -y
```

接下来，要安装图像 I/O 软件包，请输入以下命令：

```cpp
sudo apt-get install libjpeg-dev libtiff5-dev libjasper-dev libpng12-dev -y
```

之后，我们将通过输入以下命令安装两个视频 I/O 软件包：

```cpp
sudo apt-get install libavcodec-dev libavformat-dev libswscale-dev libv4l-dev -y
sudo apt-get install libxvidcore-dev libx264-dev -y
```

接下来，我们将下载并安装**Gimp Toolkit**（**GTK**）软件包。此工具包用于为我们的程序制作图形界面。我们将执行以下命令来下载和安装 GTK 软件包：

```cpp
sudo apt-get install libgtk2.0-dev libgtk-3-dev -y
sudo apt-get install libatlas-base-dev gfortran -y
```

# 下载和解压 OpenCV 4.0 及其贡献存储库

安装了这些软件包后，我们可以继续进行 OpenCV。让我们开始下载 Open CV 4.0：

1.  在终端窗口中输入以下命令：

```cpp
wget -O opencv.zip https://github.com/opencv/opencv/archive/4.0.0.zip
```

1.  下载包含一些附加模块的`opencv_contrib`存储库。输入以下命令：

```cpp
wget -O opencv_contrib.zip https://github.com/opencv/opencv_contrib/archive/4.0.0.zip
```

*步骤 1*和*步骤 2*中的命令都是单行命令。

1.  使用以下命令解压`opencv.zip`文件：

```cpp
unzip opencv.zip
```

1.  解压`opencv_contrib.zip`文件：

```cpp
unzip opencv_contrib.zip
```

解压`opencv`和`opencv_contrib`后，您应该在`pi`文件夹中看到`opencv-4.0.0`和`opencv_contrib-4.0.0`文件夹。

# 安装 Python

接下来，我们将安装 Python 3 及其一些支持工具。即使我们将使用 C++编程 OpenCV，安装并链接 Python 包与 OpenCV 仍然是一个好主意，这样您就可以选择使用 OpenCV 编写或编译 Python 代码。

要安装 Python 及其开发工具，请输入以下命令：

```cpp
sudo apt-get install python3 python3-setuptools python3-dev -y
wget https://bootstrap.pypa.io/get-pip.py
sudo python3 get-pip.py
sudo pip3 install numpy
```

安装 Python 软件包后，我们可以编译和构建 OpenCV。

# 编译和安装 OpenCV

要编译和安装 OpenCV，我们需要按照以下步骤进行：

1.  进入`opencv-4.0.0`文件夹。使用以下命令更改目录到`opencv-4.0.0`文件夹：

```cpp
cd opencv-4.0.0
```

1.  在此文件夹中创建一个`build`文件夹。为此，请输入以下命令：

```cpp
mkdir build
```

1.  要打开`build`目录，请输入以下命令：

```cpp
cd build
```

1.  更改目录到`build`后，输入以下命令：

```cpp
cmake -D CMAKE_BUILD_TYPE=RELEASE \
-D CMAKE_INSTALL_PREFIX=/usr/local \
-D BUILD_opencv_java=OFF \
-D BUILD_opencv_python2=OFF \
-D BUILD_opencv_python3=ON \
-D PYTHON_DEFAULT_EXECUTABLE=$(which python3) \
-D INSTALL_C_EXAMPLES=ON \
-D INSTALL_PYTHON_EXAMPLES=ON \
-D BUILD_EXAMPLES=ON\
-D OPENCV_EXTRA_MODULES_PATH=~/opencv_contrib-4.0.0/modules \
-D WITH_CUDA=OFF \
-D BUILD_TESTS=OFF \
-D BUILD_PERF_TESTS= OFF ..
```

在输入此命令时，请确保在终端窗口中输入两个点`..`。

1.  要启用 RPi 的所有四个内核，请在 nano 编辑器中打开`swapfile`文件：

```cpp
sudo nano /etc/dphys-swapfile
```

1.  在此文件中，搜索`CONF_SWAPSIZE=100`代码，并将值从`100`更改为`1024`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/81e9f8e3-b104-4768-b028-a36d9367b641.png)

1.  按下*Ctrl* + *O*保存此文件。您将在文件底部收到提示，询问您是否要保存此文件。按*Enter*，然后按*Ctrl *+ *X*退出。

1.  要应用这些更改，请输入以下两个命令：

```cpp
sudo /etc/init.d/dphys-swapfile stop
sudo /etc/init.d/dphys-swapfile start
```

1.  要使用 RPi 的所有四个内核编译 OpenCV，请输入以下命令：

```cpp
make -j4
```

这是最耗时的步骤，需要 1.5 到 2 小时。如果在编译时遇到任何错误，请尝试使用单个内核进行编译。

要使用单个内核进行编译，请输入以下命令：

```cpp
sudo make install
make
```

只有在使用`make -j4`命令时遇到错误时才使用前面的两个命令。

1.  要安装 OpenCV 4.0.0，请输入以下命令：

```cpp
sudo make install
sudo ldconfig 
```

我们现在已经编译并安装了 OpenCV。让我们将其连接到 Python。

# 将 OpenCV 链接到 Python

让我们按照以下步骤将 OpenCV 链接到 Python：

1.  打开`python 3.5`文件夹(`/usr/local/python/cv2/python-3.5`)：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/a1ee0334-dc02-4d84-9c54-683849c73b93.png)

在此文件夹中，您应该看到一个名为`cv2.so`或`cv2.cpython-35m-arm-linux-gnueabihf.so`的文件。如果文件名是`cv2.so`，则无需进行任何更改。如果文件名是`cv2.cpython-35m-arm-linux-gnueabihf.so`，则必须将其重命名为`cv2.so`。要重命名此文件，请输入以下命令更改目录到`python 3.5`：

```cpp
cd /usr/local/python/cv2/python-3.5
```

将此文件从`cv2.cpython-35m-arm-linux-gnueabihf.so`重命名为`cv2.so`，输入以下命令：

```cpp
sudo mv /usr/local/python/cv2/python3.5/cv2.cpython-35m-arm-linux-gnueabihf.so cv2.so
```

1.  使用以下命令将此文件移动到`dist-package`文件夹(`/usr/local/lib/python3.5/dist-packages/`)：

```cpp
sudo mv /usr/local/python/cv2/python-3.5/cv2.so /usr/local/lib/python3.5/dist-packages/cv2.so
```

1.  要测试 OpenCV 4.0.0 是否正确链接到 Python 3，请在终端窗口中输入`cd ~`进入`pi`目录。接下来，输入`python3`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/ad9421bb-6a69-49b1-99cb-f6da0bd9150d.png)

1.  您应该看到一个三角括号。输入`import cv2`。

1.  要检查 OpenCV 版本，请输入`cv2.__version__`。如果看到`opencv 4.0.0`，这意味着 OpenCV 已成功安装并与 Python 软件包链接：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/e257f115-e220-444b-9e14-293973b6eca4.png)

1.  输入`exit()`并按*Enter*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/9fec64e2-9e7f-46bb-8e97-957f02c601bb.png)

安装 OpenCV 后，我们需要将`CONF_SWAPSIZE`重置为`100`：

1.  打开`swapfile`：

```cpp
sudo nano /etc/dphys-swapfile
```

1.  将`CONF_SWAPSIZE`更改为`100`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/394f4e62-3813-4d41-8430-8b1455a68a90.png)

1.  要应用这些更改，请输入以下命令：

```cpp
sudo /etc/init.d/dphys-swapfile stop
sudo /etc/init.d/dphys-swapfile start
```

您已成功在树莓派上安装了 OpenCV 4.0.0。我们现在准备将 RPi 相机连接到 RPi。

# 启用并连接 RPi 相机到 RPi

在连接 RPi 相机到 RPi 之前，我们需要从 RPi 配置中启用相机选项：

1.  打开一个终端窗口并输入`sudo raspi-config`打开 RPi 配置。

1.  选择“高级选项”并按*Enter*打开它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/d7ddf9aa-8152-4cc6-928b-e15964e60851.png)

1.  选择相机选项并按*Enter*打开它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/d7e4e53a-491f-4a57-9095-254f4638e5a0.png)

1.  选择“是”并按*Enter*启用相机选项：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/be9db14b-36c0-415a-9bbf-4f5e877a4b70.png)

1.  选择确定并按*Enter*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/5e527a4a-f295-4b17-8607-37dfbc564bb4.png)

1.  退出 RPi 配置并关闭 RPi。

在连接 RPi 相机到 RPi 时，请确保 RPi 已关闭。

现在我们已经完成了设置，让我们连接相机。

# 连接 RPi 相机到 RPi

连接 RPi 相机到 RPi 是一个简单但又微妙的过程。RPi 相机有一根连接的带线。我们必须将这根带线插入 RPi 的相机插槽中，该插槽位于 LAN 端口和 HDMI 端口之间：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/e87cff4c-92e6-4ff5-ab66-a4565df03f24.png)

RPi 相机上的带线由前面的蓝色条组成，后面没有：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/75439b70-bb7f-4316-9ed4-1217e5bac8b4.png)

现在我们了解了组件和端口，让我们开始连接它们：

1.  轻轻抬起相机插槽的盖子：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/496b322c-4916-47bb-af90-bccf043aed9a.png)

1.  将相机带插入插槽，确保带子上的蓝色胶带面向 LAN 端口。

1.  按下盖子锁定相机带线：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/536f5eb1-d900-4f7f-be3c-95f1aab69d61.png)

就是这样——您的 RPi 相机现在已准备好拍照和录制视频。

# 安装 RPi 相机在机器人上

让我们在机器人上安装 RPi 相机；您需要一个 RPi 相机盒子。在[amazon.com](http://amazon.com)上快速搜索`RPi 相机盒子`将显示以下情况：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/6a379ac6-97f9-413e-995e-b5634e7d872c.png)

我不推荐这个特定的情况，因为它没有正确安装我的 RPi 相机模块。当盒子关闭时，我的 RPi 相机的镜头没有正确对齐这个相机盒子的小孔。

由于我住在印度，在亚马逊印度网站([www.amazon.in](http://www.amazon.in))上找不到好的 RPi 相机盒子，而且可用的盒子价格昂贵。我最终使用的盒子来自一个名为[www.robu.in](http://www.robu.in)的印度电子商务网站，只花了我 90 卢比（不到 2 美元）。在从电子商务网站购买相机盒子或相机支架之前，请检查评论以确保它不会损坏您的 RPi 相机。

我使用的 RPi 相机盒子的图像显示在以下图像中。我从一个名为[www.robu.in](http://www.robu.in)的印度网站购买了这个盒子。在这个网站上，搜索`树莓派相机支架模块`以找到这个相机支架：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/5edb81df-b762-43f4-8229-f1e7909a64d9.png)

尽管此摄像头支架包含四个小螺母和螺栓将 RPi 摄像头固定到摄像头支架上，但我发现螺母和螺栓的螺纹不准确，并且将 RPi 摄像头固定到摄像头支架上非常困难。因此，我使用了四小块双面胶带，并将其粘贴到 RPi 摄像头的孔中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/65232c5d-c15a-4558-8cfa-8418d6510bc3.png)

接下来，我将 RPi 摄像头安装到摄像头支架上。在下图中，RPi 摄像头被倒置安装。因此，当我们捕获图像时，图像将呈倒置状态，为了正确查看图像，我们需要翻转它（在 OpenCV 中解释了在第七章中水平和垂直翻转图像的过程，*使用 OpenCV 构建对象跟随机器人*）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/b51d7df9-723c-4abe-9eb6-81caa20d3ad9.png)

之后，我使用双面胶带在 RPi 外壳顶部安装了摄像头支架，从而将 RPi 摄像头安装在机器人上：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/ba3d6a10-11d8-4b86-a561-d7ade37e7ca4.png)

现在我们已经将摄像头外壳安装到机器人上，让我们看看如何使用 RPi 摄像头捕获图像和视频。

# 使用 RPi 摄像头捕获图像和视频

让我们看看如何在 RPi 上拍照和录制视频。打开终端窗口，输入以下命令：

```cpp
raspistill -o image1.jpg
```

在此命令中，我们使用`raspistill`拍摄静态图片，并将其保存为`image1.jpg`。

由于终端窗口指向`pi`目录，因此此图像保存在`pi`文件夹中。要打开此图像，请打开`pi`文件夹，在其中您将看到`image1.jpg`。使用 RPi 摄像头捕获的图像具有本机分辨率为 3,280 x 2,464 像素：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/7935ab8e-1b77-479d-9afd-560a4a5bb2d0.png)

`image1`的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/9107747b-66fe-47cd-af30-fe1e703d3c52.png)

如果我们想水平翻转图像，可以添加`-hf`命令，如果要垂直翻转图像，可以在`raspistill`代码中添加`-vf`命令：

```cpp
raspistill -hf -vf -o image2.jpg
```

`image2.jpg`文件也保存在`pi`文件夹中，其输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/ba63edc7-b341-427c-b444-a514909d811e.png)

现在我们已经使用 RPi 摄像头捕获了图像，让我们录制并查看视频。

# 使用 RPi 摄像头录制视频

现在我们知道如何使用 RPi 摄像头拍照，让我们看看如何录制视频。录制视频剪辑的命令如下：

```cpp
raspivid -o video1.h264 -t 5000 
```

如下截图所示，上述命令不会产生任何输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/00cea86c-1fc4-4902-a4d0-ba5e22cb2c35.png)

在我们的命令中，我们使用`raspivid`录制视频，并将其命名为`video1`。我们以`h264`格式录制了视频。数字`5000`代表 5000 毫秒，也就是说，我们录制了一个 5 秒的视频。您可以打开`pi`文件夹，双击视频文件以打开它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/92bdd50f-5568-4a28-a8a3-3f62e556f4b4.png)

现在我们知道如何拍照和录制视频，让我们安装`v4l2`驱动程序，以便 OpenCV 库可以检测到 RPi 摄像头。

# 安装 v4l2 驱动程序

OpenCV 库默认可以识别连接到 RPi USB 端口的 USB 摄像头，但无法直接检测 RPi 摄像头。要识别我们的 RPi 摄像头，我们需要在模块文件中加载`v4l2`驱动程序。要打开此文件，请在终端窗口中输入以下命令：

```cpp
sudo nano /etc/modules
```

要加载`v4l2`驱动程序，请在以下文件中添加`bcm2835-v4l2`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2e9c0b29-5143-4e74-b14c-2b229999dd33.png)

按下*Ctrl* + *O*，然后按*Enter*保存此文件，按下*Ctrl* + *X*退出文件，然后重新启动您的 RPi。重新启动后，OpenCV 库将识别 RPi 摄像头。

# 使用 OpenCV 读取图像

在 RPi 相机上玩了一会儿之后，让我们使用 OpenCV 函数编写一个简单的 C++程序来显示图像。在这个程序中，我们首先从一个特定的文件夹中读取图像，然后在新窗口中显示这个图像：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/b18a5571-b2f1-434c-baa4-eb92163ea7ce.png)

要显示图像，我们首先需要一张图像。在`pi`文件夹中，我创建了一个名为`Data`的新文件夹，在其中，我复制了一张名为`Car.png`的图像。在同一个文件夹中，我创建了`DisplayImage.cpp`文件，我们将在其中编写显示图像的程序。`DisplayImage.cpp`程序可以从本书的 GitHub 存储库的`Chapter06`文件夹中下载。代码如下：

```cpp
#include <iostream>
#include <stdio.h>
#include <opencv2/opencv.hpp>

using namespace cv;
using namespace std;
int main()
{

Mat img;

img = imread("Car.jpg");

imshow("Car Image", img);

waitKey(0);

return 0;
}
```

在上述代码中，我们首先声明了`opencv.hpp`库，以及基本的 C++库。然后声明了`cv`命名空间，它是 OpenCV 库的一部分。在`main`函数内部，我们声明了一个名为`img`的矩阵（`Mat`）变量。

接下来，使用`imread（）`函数读取`Car.jpg`图像，并将值存储在`img`变量中。如果图像和`.cpp`文件在同一个文件夹中，只需在`imread（）`函数中写入图像名称。如果图像在不同的文件夹中，则应在`imread`函数中提及图像的位置。

`imshow（）`函数用于在新窗口中显示汽车图像。`imshow（）`函数接受两个参数作为输入。第一个参数是窗口文本（`"Car Image"`），第二个参数是要显示的图像的变量名（`img`）。

`waitKey（0）`函数用于创建无限延迟，也就是说，`waitKey（0）`将无限地显示汽车图像，直到您按下任意键。按下键后，将执行下一组代码。由于在`waitKey（0）`函数之后没有任何代码，程序将终止，汽车图像窗口将关闭。

要在 RPi 内部编译和构建 OpenCV 代码，我们需要在编译和构建框内添加以下行：

1.  单击**构建选项**，然后选择**设置构建命令**。在编译框内，输入以下命令：

```cpp
g++ -Wall $(pkg-config --cflags opencv) -c "%f" -lwiringPi
```

1.  在构建框内，输入以下命令，然后单击“确定”：

```cpp
g++ -Wall $(pkg-config --libs opencv) -o "%e" "%f" -lwiringPi
```

1.  单击编译按钮编译代码，然后单击构建按钮测试输出。在输出中，将创建一个新窗口，在其中将显示汽车图像：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/dce0a5f0-4a99-43c6-9f04-da1e4162ac6c.png)

1.  如果按任意键，程序将终止，汽车图像窗口将关闭。

# 总结

在本章中，我们专注于在树莓派上安装 OpenCV。您已经了解了 RPi 相机模块。设置 RPi 相机后，您使用 RPi 相机拍摄了照片并录制了一个短视频剪辑。

在下一章中，我们将使用 OpenCV 库编写 C++程序。您将学习不同的图像处理概念，以便可以扫描、阈值化和识别对象。在识别对象之后，我们将为机器人编写程序，使其跟随该对象。

# 问题

1.  OpenCV 的全称是什么？

1.  RPi 相机拍摄的图像分辨率是多少？

1.  使用 RPi 相机拍摄图像的命令是什么？

1.  使用 RPi 相机录制视频的命令是什么？

1.  Raspbian OS 在 8GB 和 32GB SD 卡上占用的内存百分比是多少？


# 第七章：使用 OpenCV 构建一个目标跟随机器人

在上一章中安装了 OpenCV 之后，现在是时候使用 OpenCV 库执行图像处理操作了。在本章中，我们将涵盖以下主题：

+   使用 OpenCV 进行图像处理

+   查看来自 Pi 摄像头的视频源

+   构建一个目标跟随机器人

# 技术要求

对于本章没有新的技术要求，但是您需要以下内容来执行示例：

+   用于检测红色、绿色或蓝色的球

+   安装在机器人上的 Pi 摄像头和超声波传感器

本章的代码文件可以从[`github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter07`](https://github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter07)下载。

# 使用 OpenCV 进行图像处理

在本节中，我们将查看 OpenCV 库的重要函数。之后，我们将使用 OpenCV 库编写一个简单的 C++程序，并对图像执行不同的图像处理操作。

# OpenCV 中的重要函数

在编写任何 OpenCV 程序之前，了解 OpenCV 中的一些主要函数以及这些函数可以给我们的输出是很重要的。让我们从查看这些函数开始：

+   **`imread()`**: `imread()`函数用于从 Pi 摄像头或网络摄像头读取图像或视频。在`imread()`函数内部，我们必须提供图像的位置。如果图像和程序文件在同一个文件夹中，我们只需要提供图像的名称。但是，如果图像存储在不同的文件夹中，那么我们需要在`imread`函数内提供图像的完整路径。我们将从`imread()`函数中存储的图像值存储在一个矩阵（`Mat`）变量中。

如果图像和`.cpp`文件在同一个文件夹中，代码如下所示：

```cpp
Mat img = imread("abcd.jpg"); //abcd.jpg is the image name
```

如果图像和`.cpp`文件在不同的文件夹中，代码如下所示：

```cpp
Mat img = imread("/home/pi/abcd.jpg"); //abcd image is in 
                                      // the Pi folder

```

+   `imshow()`: `imshow()`函数用于显示或查看图像：

```cpp
imshow("Apple Image", img);
```

`imshow()`函数包括两个参数，如下：

+   +   第一个参数是窗口文本

+   第二个参数是要显示的图像的变量名

`imshow()`函数的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/9cb8e918-e21b-4484-994c-a53e49eaf1f6.png)

+   `resize()`: `resize()`函数用于调整图像的尺寸。当用户同时使用多个窗口时，通常会使用此函数：

```cpp
resize(img, rzimg, cvSize(400,400));  //new width is 400 
                                     //and height is 400
```

此函数包括三个参数：

+   +   第一个参数是要调整大小的原始图像（`img`）的变量名。

+   第二个参数是将调整大小的新图像（`rzimg`）的变量名。

+   第三个参数是`cvSize`，在其中输入**新宽度**和**高度值**。

`resize()`函数的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2fcade67-80dc-476e-b1d2-1a7ad3138fa3.png)

+   `flip()`: 此函数用于水平翻转、垂直翻转或同时进行两者：

```cpp
flip(img, flipimage, 1)
```

此函数包括三个参数：

+   +   第一个参数（`img`）是原始图像的变量名。

+   第二个参数（`flipimage`）是翻转后的图像的变量名。

+   第三个参数是翻转类型；`0`表示垂直翻转，`1`表示水平翻转，`-1`表示图像应同时水平和垂直翻转。

`flip()`函数的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2e0a5b4a-3110-465f-af3f-f2e5d0309fe8.png)

+   `cvtColor()`: 此函数用于将普通的 RGB 彩色图像转换为灰度图像：

```cpp
cvtColor(img, grayimage, COLOR_BGR2GRAY)
```

此函数包括三个参数：

+   +   第一个参数（`img`）是原始图像的变量名

+   第二个参数（`grayimage`）是将转换为灰度的新图像的变量

+   第三个参数，`COLOR_BGR2GRAY`，是转换类型；BGR 是 RGB 倒过来写的

`cvtColor()`函数的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/6bb5991a-bb09-4079-b1e7-36fb272f016d.png)

+   `threshold()`: 阈值化方法用于分离代表对象的图像区域。简单来说，阈值化用于识别图像中的特定对象。阈值化方法接受源图像（`src`）、阈值和最大阈值（`255`）作为输入。它通过比较源图像的像素值与阈值来生成输出图像（`thresimg`）：

```cpp
threshold(src, thresimg, threshold value, max threshold value, threshold type);
```

阈值函数由五个参数组成：

+   +   第一个参数（`src`）是要进行阈值化的图像的变量名。

+   第二个参数（`thresimg`）是阈值化图像的变量名。

+   第三个参数（`阈值`）是阈值（从 0 到 255）。

+   第四个参数（`最大阈值`）是最大阈值（`255`）。

+   第五个参数（`阈值类型`）是阈值化类型。

一般来说，有五种类型的阈值化，如下所示：

+   +   **0-二进制**：二进制阈值化是阈值化的最简单形式。在这种阈值化中，如果源图像（`src`）上的任何像素值大于阈值，则在输出图像（`thresimg`）中，该像素将被设置为最大阈值（`255`），并且将变为白色。另一方面，如果源图像上的任何像素值小于阈值，则在输出图像中，该像素值将被设置为`0`，并且将变为黑色。

例如，在以下代码中，阈值设置为`85`，最大阈值为`255`，阈值类型为用数字`0`表示的二进制：

```cpp
threshold(src, thresimg,85, 255, 0);
```

因此，如果苹果图像源图像上的任何像素值大于阈值（即大于`85`），那么这些像素将在输出图像中变为白色。同样，源图像上值小于阈值的像素将在输出图像中变为黑色。

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/dcdf5b7c-3085-4601-a90f-fbb742150def.png)

二进制阈值化

+   +   **1-二进制反转**：二进制反转阈值化正好与二进制阈值化相反。在这种类型的阈值化中，如果源图像的像素值大于阈值，则输出图像的像素将变为黑色（`0`），如果源图像的像素值小于阈值，则输出图像的像素将变为白色（`255`）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/64064bd2-0ac0-4793-a79a-c5600f8f2d18.png)

二进制反转阈值化

+   +   **2-截断** **阈值化**：在截断阈值化中，如果`src`源图像上的任何像素值大于阈值，则在输出图像中，该像素将被设置为阈值。另一方面，如果`src`源图像上的任何像素值小于阈值，则在输出图像中，该像素将保留其原始颜色值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/fcf7b239-5bf5-4a6f-a6d7-d76f05083cb9.png)

截断阈值化

+   +   **3-阈值为零**：在这种阈值化中，如果`src`源图像上的任何像素值大于阈值，则在输出图像中，该像素将保留其原始颜色值。另一方面，如果`src`源图像上的任何像素值小于阈值，则在输出图像中，该像素将被设置为`0`（即黑色）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/6f3a8fc1-a1b9-4010-9f76-43c7598b936f.png)

阈值为零

+   +   **4-阈值为零反转**：在这种阈值化中，如果`src`上的任何像素值大于阈值，则在输出图像中，该像素将被设置为`0`。如果`src`上的任何像素值小于阈值，则在输出图像中，该像素将保留其原始颜色值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2c0e2d36-c417-4ab2-9ca8-6369d7808e9d.png)

阈值为零反转

+   `inRange()`: `inRange()`函数是阈值函数的高级形式。在这个函数内部，我们必须输入我们想要识别的对象的最小和最大 RGB 颜色值。`inRange()`函数由四个参数组成：

+   第一个参数（`img`）是要进行阈值处理的图像的变量名。

+   有两个`Scalar`函数。在第一个`Scalar`函数中的第二个参数中，我们必须输入对象的最小 RGB 颜色。

+   在第三个参数中，也就是第二个`Scalar`函数中，我们将输入对象的最大 RGB 颜色值。

+   第四个参数（`thresImage`）代表阈值图像的输出：

```cpp
inRange(img, Scalar(min B,min G,min R), Scalar(max B,max G,max R),thresImage)
```

**图像矩**——图像矩的概念源自**矩**，它在力学和统计学中用于描述一组点的空间分布。在图像处理或计算机视觉中，图像矩用于找到形状的**质心**，即形状中所有点的平均值。简单来说，图像矩用于在我们从整个图像中分割出对象后找到任何对象的中心。例如，在我们的情况下，我们可能想要找到苹果的中心。从图像计算对象的中心的**图像矩公式**如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/03fefae2-083d-4dc8-a8ac-d5a21dc4d18c.png)

+   +   *x*代表图像的宽度

+   *y*代表图像的高度

+   *M10*代表图像中所有*x*值的总和

+   *M01*代表图像中所有*y*值的总和

+   *M00*代表图像的整个区域

+   `circle`: 正如其名，这个函数用于画圆。它有五个参数作为输入：

+   第一个参数（`img`）是你要在其上画圆的图像的变量名。

+   第二个参数（`point`）是圆的中心（*x*，*y*位置）点。

+   第三个参数（`radius`）是圆的半径。

+   第四个参数（`Scalar(B,G,R)`）是为圆着色的；我们使用`Scalar()`函数来做到这一点。

+   第五个参数（`thickness`）是圆的厚度：

```cpp
circle(img, point, radius, Scalar(B,G,R),thickness);
```

# 使用 OpenCV 进行对象识别

现在我们已经了解了 OpenCV 的重要功能，让我们编写一个程序来从图像中检测一个有颜色的球。在我们开始之前，我们必须做的第一件事是拍摄球的合适照片。你可以用任何球来做这个项目，但要确保球是单色的（红色、绿色或蓝色的球是强烈推荐的），并且不是多色的。我在这个项目中使用了一个绿色的球：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/b106b7e4-d5e1-4315-9a5f-780605e86b64.png)

# 拍摄图像

为了捕捉你的球的图像，把它放在一些黑色的表面上。我把我的绿色球放在一个黑色的手机壳上：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/6682ea0b-0d22-4d37-9f4c-f97c19c5f083.png)

如果你的球是黑色，或者颜色较暗，你可以把球放在一个颜色较浅的表面上。这是为了确保球的颜色和背景的颜色之间有很高的对比度，这将有助于我们后面的阈值处理。

在拍摄图像时，确保球上没有白色斑块，因为这可能会在后面的阈值处理中造成问题：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/a50b303b-299f-4688-a872-7b1113acd8c0.png)

左边的照片有一个大的白色区域，因为光线太亮。右边，球被适当照亮。

一旦你对拍摄的图像满意，将其传输到你的笔记本电脑上。

# 找到 RGB 像素值

现在我们将通过以下步骤检查球上不同点的 RGB 像素值来找到球的 RGB 像素值：

1.  打开画图并打开保存的球的图像，如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/ed5a0ead-7fce-4d7a-b840-4bac834a0314.png)

1.  接下来，使用取色器工具，在球的任何位置单击取样颜色：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/5a72281c-cd2c-488c-9a25-862740b7f79e.png)

颜色 1 框将显示被点击的颜色的样本。在我的情况下，这是绿色：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/55d4a8ea-436c-44b7-809a-ced4e08fef9e.png)

1.  如果您点击“编辑颜色”选项，您将看到该像素的 RGB 颜色值。在我的情况下，绿色像素的 RGB 颜色值为红色：`61`，绿色：`177`，蓝色：`66`。记下这些值，以备后用：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/79be885f-8be2-4410-9213-6f295f4e68af.png)

1.  现在，再次选择取色器选项，点击球的另一个彩色区域，找出该像素的 RGB 颜色值。再次记录这个值。重复 13 到 14 次，确保包括球上最浅和最暗的颜色：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/73e809be-ab83-4576-8502-61e1f9202d22.png)

我已经记录了球边缘六个点的 RGB 值，球周围随机位置的四个点的 RGB 值，以及颜色为浅绿色或深绿色的六个点的 RGB 值。找到 RGB 值后，突出显示最低的红色、绿色和蓝色值，以及最高的红色、绿色和蓝色值。我们将在程序中稍后使用这些值来对图像进行阈值处理。

1.  现在，您需要将这个图像传输到您的 RPi。我通过**Google Drive**传输了我的图像。我通过将图像上传到 Google Drive，然后在我的 RPi 内打开默认的 Chromium 网络浏览器，登录我的 Gmail 账户，打开 Google Drive，并下载图像来完成这一步。

# 物体检测程序

用于检测绿色球的程序名为`ObjectDetection.cpp`，我将其保存在`OpenCV_codes`文件夹中。我还将`greenball.png`图像复制到了这个文件夹中。您可以从 GitHub 存储库的`Chapter07`文件夹中下载`ObjectDetection.cpp`程序。因此，用于检测绿色球的程序如下：

```cpp
#include <iostream>
#include<opencv2/opencv.hpp>
#include<opencv2/core/core.hpp>
#include<opencv2/highgui/highgui.hpp>
#include<opencv2/imgproc/imgproc.hpp>

using namespace cv;
using namespace std;

int main()
{

 Mat img, resizeimg,thresimage;
 img = imread("greenball.png");
 imshow("Green Ball Image", img);
 waitKey(0);

 resize(img, resizeimg, cvSize(640, 480));
 imshow("Resized Image", resizeimg);
 waitKey(0);

 inRange(resizeimg, Scalar(39, 140, 34), Scalar(122, 245, 119), thresimage);
 imshow("Thresholded Image", thresimage);
 waitKey(0);

 Moments m = moments(thresimage,true);
 int x,y;
 x = m.m10/m.m00;
 y = m.m01/m.m00;
 Point p(x,y);
 circle(img, p, 5, Scalar(0,0,200), -1);
 imshow("Image with center",img);
 waitKey(0);

 return 0;
}
```

在前面的程序中，我们导入了四个 OpenCV 库，它们是`opencv.hpp`、`core.hpp`、`highgui.hpp`和`imgproc.hpp`。然后我们声明了 OpenCV 库的`cv`命名空间。

以下是前面程序的解释：

1.  在`main`函数内，我们声明了三个矩阵变量，分别为`img`、`resizeimg`和`thresimage`。

1.  接下来，`imread()`函数读取`greenball.png`文件，并将其存储在`img`变量中。

1.  `imshow("Green Ball Image", img)`行将在新窗口中显示图像，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/78b0c58b-4365-4476-8a93-ae7f0cff4575.png)

1.  之后，`waitKey(0)`函数将等待键盘输入。然后执行下一组代码。一旦按下任意键，将执行调整图像大小的下两行代码。

1.  `resize`函数将调整图像的宽度和高度，使得图像的新宽度为`640`，高度为`480`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/cd1136d0-cd91-4c74-ad86-b7b2c19c79d3.png)

1.  然后使用`inRange`函数执行阈值处理操作。在第一个`Scalar`函数内，我输入了我的球的绿色的最小 RGB 值，在第二个`Scalar`函数内，我输入了最大 RGB 值。阈化后的图像存储在`thresimage`变量中。

在`Scalar`函数内，我们首先输入蓝色值，然后是绿色，最后是红色。

1.  阈值处理后，球的颜色将变为白色，图像的其余部分将变为黑色。球中间的一些部分将呈现为黑色，这是正常的。如果白色内部出现大面积黑色，这意味着阈值处理没有正确进行。在这种情况下，您可以尝试修改`Scalar`函数内的 RGB 值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/7dbbcb36-3994-479a-baff-e29aae6ba464.png)

1.  接下来，使用`moments`函数，我们找到对象的中心。

1.  在`moments(thresimage,true)`行，我们将`thresimage`变量作为输入。

1.  在接下来的三行代码中，我们找到白色区域的中心并将该值存储在点变量`p`中。

1.  之后，为了显示球的中心，我们使用`circle`函数。在圆函数内部，我们使用`img`变量，因为我们将在原始图像上显示圆点。接下来，点变量`p`告诉函数我们在哪里显示点。圆形点的宽度设置为`5`，圆形点的颜色将是红色，因为我们只填充了`Scalar`函数的最后一个参数，表示颜色为红色。如果要设置其他颜色，可以更改`Scalar`函数内的颜色值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/59d0c10b-6ec9-4fb7-800c-c3ef54c1006d.png)

1.  按任意键再次按下`waitKey(0)`函数，将关闭除终端窗口之外的所有窗口。要关闭终端窗口，请按*Enter*。

通过上述程序，我们已经学会了如何调整大小、阈值处理，并在绿色球的图像上生成一个点（红点）。在下一节中，我们将对实时视频反馈执行一些图像识别操作。

# OpenCV 相机反馈程序

现在，我们将编写一个简单的 C++程序来查看来自 Pi 相机的视频反馈。视频查看程序如下。该程序名为`Camerafeed.cpp`，您可以从 GitHub 存储库的`Chaper07`文件夹中下载：

```cpp
int main()
{
 Mat videoframe;

VideoCapture vid(0);

if (!vid.isOpened())
 {
cout<<"Error opening camera"<<endl;
 return -1;
 }
 for(;;)
 {
 vid.read(videoframe);
 imshow("Frame", videoframe);
 if (waitKey(1) > 0) break;
 }
 return 0;
}
```

OpenCV 库和命名空间声明与先前程序类似：

1.  首先，在`main`函数内部，我们声明了一个名为`videoframe`的矩阵变量。

1.  接下来，使用`VideoCapture`数据类型从 Pi 相机捕获视频反馈。它有一个名为`vid(0)`的变量。`vid(0)`变量内的`0`数字表示相机的索引号。目前，由于我们只连接了一个相机到 RPi，Pi 相机的索引将为`0`。如果您将 USB 相机连接到树莓派，那么 USB 相机的索引将为`1`。通过更改索引号，您可以在 Pi 相机和 USB 相机之间切换。

1.  接下来，我们指定如果相机无法捕获任何视频反馈，则应调用`!vid.isOpened()`条件。在这种情况下，终端将打印出`"Error opening camera"`消息。

1.  之后，`vid.read(videoframe)`命令将读取相机反馈。

1.  使用`imshow("Video output", videoframe)`行，我们现在可以查看相机反馈。

1.  `waitKey`命令将等待键盘输入。一旦按下任意键，它将退出代码。

这就是您可以使用 Pi 相机查看视频反馈的方法。

# 构建一个目标跟踪机器人

在对图像进行阈值处理并从 Pi 相机查看视频反馈之后，我们将结合这两个程序来创建我们的目标跟踪机器人程序。

在本节中，我们将编写两个程序。在第一个程序中，我们将球放在相机前面，并通过在球的中心创建一个点（使用矩形）来追踪它。接下来，我们将移动球**上**、**下**、**左**和**右**，并记录相机上不同位置的点值。

在第二个程序中，我们将使用这些点值作为输入，并使机器人跟随球对象。

# 使用矩形进行球追踪

在跟踪球之前，机器人应首先能够使用 Pi 相机追踪它。在编写程序之前，让我们看看我们将如何追踪球。

# 编程逻辑

首先，我们将相机分辨率调整为 640 x 480，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/573110e3-d48d-4160-a850-58337f40e3d3.png)

调整宽度和高度后，我们将相机屏幕水平分为三个相等的部分：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/58b91348-dc48-4cff-a1e8-39b77c1dd6f4.png)

从 0 到 214 的**x 坐标值**代表左侧部分。从 214 到 428 的**x 坐标值**代表前进部分，而从 428 到 640 的**x 坐标值**代表右侧部分。我们不需要编写任何特定的程序来将摄像头屏幕划分为这三个不同的部分，我们只需要记住每个部分的最小和最大**x 点值**。

接下来，我们将对球对象进行阈值处理。之后，我们将使用矩和在球的中心生成一个点。我们将在控制台中打印点值，并检查屏幕特定部分的*x*和*y*点值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/f14fbb93-e742-4108-b319-a23790fa82b9.png)

如果球在**前进**部分，**x 坐标值**必须在**214**和**428**之间。由于我们不是垂直地划分屏幕，所以不需要考虑*y*值。现在让我们开始球追踪程序。

# 球追踪程序

`BallTracing.cpp`程序如下。您可以从 GitHub 存储库的`Chapter07`文件夹中下载此程序：

```cpp
int main()
{
  Mat videofeed,resizevideo,thresholdvideo;
  VideoCapture vid(0);
  if (!vid.isOpened())
  {
    return -1;
  } 
  for (;;)
  { 
    vid.read(videofeed);
  resize(videofeed, resizevideo, cvSize(640, 480));
  flip(resizevideo, resizevideo, 1);

  inRange(resizevideo, Scalar(39, 140, 34), Scalar(122, 245, 119), thresholdvideo); 

  Moments m = moments(thresholdvideo,true);
  int x,y;
  x = m.m10/m.m00;
  y = m.m01/m.m00; 
  Point p(x,y);

  circle(resizevideo, p, 10, Scalar(0,0,128), -1);

  imshow("Image with center",resizevideo);
    imshow("Thresolding Video",thresholdvideo);

  cout<<Mat(p)<< endl;

  if (waitKey(33) >= 0) break;
  }
  return 0;
}
```

在`main`函数内，我们有三个矩阵变量，名为`videofeed`、`resizevideo`和`thresholdvideo`。我们还声明了一个名为`vid(0)`的`VideoCapture`变量来捕获视频。

以下步骤详细说明了`BallTracing.cpp`程序：

1.  在`for`循环中，`vid.read(videofeed)`代码将读取摄像头视频。

1.  使用`resize`函数，我们将摄像头分辨率调整为 640 x 480。调整大小后的视频存储在`resizevideo`变量中。

1.  然后，使用`flip`函数，我们水平翻转调整大小后的图像。翻转后的视频输出再次存储在`resizevideo`变量中。如果我们不水平翻转视频，当你向左移动时，球会看起来好像在右侧移动，反之亦然。如果您将树莓派相机倒置安装，则需要垂直翻转调整大小后的图像。要垂直翻转，将第三个参数设置为`0`。

1.  接下来，使用`inRange`函数，我们对视频进行阈值处理，使彩色球从图像的其余部分中脱颖而出。阈值化后的视频输出存储在`thresholdvideo`变量中。

1.  使用`moments`，我们找到了存储在点变量`p`中的球的中心。

1.  使用`circle`函数，在`resizevideo`视频中显示一个红点在球上。

1.  第一个`imshow`函数将显示调整大小后的(`resizedvideo`)视频，而第二个`imshow`函数将显示阈值化后的(`thresholdvideo`)视频：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/f05e7531-1c94-4573-ba08-46c39265d628.png)

在上面的屏幕截图中，左窗口显示了`resizevideo`的视频，我们看到绿色球上的红点。右窗口显示了阈值视频，其中只有球的区域是白色的。

1.  最后，`cout<<Mat(p)<<endl;`代码将在控制台内显示红点的*x*和*y*点值。当您移动球时，红点也会随之移动，并且红点的*x*和*y*位置将显示在控制台内。

从上面的屏幕截图中，方括号内的值`[298 ; 213]`是点值。因此，我的情况下红点的*x*值在 298 到 306 的范围内，*y*值在 216 到 218 的范围内。

# 设置物体跟随机器人

跟踪球的位置后，剩下的就是让我们的机器人跟随球。我们将使用`x`和`y`坐标值作为输入。然而，在跟随球的同时，我们还必须确保机器人与球的距离适当，以免与球或拿着球的人发生碰撞。为此，我们还将把超声波传感器连接到我们的机器人上。对于这个项目，我已经通过电压分压电路将超声波传感器的`trigger`引脚连接到`wiringPi pin no 12`，将`echo`引脚连接到`wiringPi pin no 13`。

# 物体跟随机器人程序

物体跟随机器人程序基本上是第四章中的避障程序和前面的球追踪程序的组合。该程序名为`ObjectFollowingRobot.cpp`，您可以从 GitHub 存储库的`Chapter07`文件夹中下载：

```cpp
int main()
 { 
...
 float distance = (totalTime * 0.034)/2;

 if(distance < 15)
 {
 cout<<"Object close to Robot"<< " " << Mat(p)<< " " <<distance << " cm" << endl;
 stop();
 }

 else{ 
      if(x<20 && y< 20)
      {
      cout<<"Object not found"<< " " << Mat(p)<< " " <<distance << " cm" << endl;
      stop();
      }
      if(x > 20 && x < 170 && y > 20 )
      {
      cout<<"LEFT TURN"<< " " << Mat(p)<< " " <<distance << " cm" << endl;
      left();
      }
      if(x > 170 && x < 470)
      {
      cout<<"FORWARD"<< " " << Mat(p)<< " " <<distance << " cm" << endl;
      forward();
      }
      if(x > 470 && x < 640)
      {
      cout<<"RIGHT TURN"<< " " << Mat(p)<< " " <<distance << " cm" << endl;
      right();
      }

      }
      if (waitKey(33) >= 0) break;
      }
       return 0;
}
```

在`main`函数中，计算距离、对视频进行阈值处理并将点放在球的中心后，让我们来看看程序的其余部分：

1.  第一个`if`条件（`if(distance < 15)`）将检查机器人距离物体是否为 15 厘米。如果距离小于 15 厘米，机器人将停止。前进、左转、右转和停止功能在`main`函数上方声明。

1.  在`stop()`函数下，`cout`语句将首先打印消息`"Object close to Robot"`。之后，它将打印点（x，y）值（`Mat(p)`），然后是`distance`值。在每个`if`条件内，`cout`语句将打印区域（如`LEFT`，`FORWARD`或`RIGHT`），点值和`distance`值。

1.  如果距离大于 15 厘米，将执行`else`条件。在`else`条件内，有三个`if`条件来找到球的位置（使用上面的红点作为参考）。

1.  现在，一旦摄像头被激活，或者当球移出摄像头的视野时，红点（点）将重置到屏幕的极左上角的位置`x:0`，`y:0`。`else`块内的第一个`if`条件（`if(x<20 && y< 20)`）将检查红点的位置在`x`和`y`轴上是否都小于 20。如果是，机器人将停止。

1.  如果`x`位置在 20 和 170 之间，`y`位置大于 20，红点将在`LEFT`区域，机器人将向`LEFT`转动。

1.  在这个程序中，我已经减小了`LEFT`和`RIGHT`区域的宽度，并增加了`FORWARD`区域的宽度，如下图所示。您可以根据需要修改每个区域的宽度：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/a53a8bd1-4f76-4ab6-aaf4-bc0c0a18646b.png)

1.  如果`x`位置在 170 和 470 之间，红点在`FORWARD`区域，机器人将向`FORWARD`移动。

1.  如果`x`位置在 470 和 640 之间，红点在`RIGHT`区域，机器人将向`RIGHT`转动。

使用移动电源为您的机器人供电，以便它可以自由移动。接下来，编译程序并在您的 RPi 机器人上构建它。只要球不在机器人面前，红点将保持在屏幕的极左上角，机器人将不会移动。如果您将球移动到摄像头前，并且距离机器人 15 厘米，机器人将开始跟随球。

随着机器人跟随球，球的颜色会因外部因素（如阳光或房间内的光线）而变化。如果房间里的光线较暗，球对机器人来说会显得稍暗。同样，如果房间里的光线太亮，球的某些部分也可能显得白色。这可能导致阈值处理无法正常工作，这可能意味着机器人无法顺利跟随球。在这种情况下，您需要调整 RGB 值。

# 总结

在本章中，我们研究了 OpenCV 库中的一些重要函数。之后，我们对这些函数进行了测试，并从图像中识别出了一个物体。接下来，我们学习了如何从树莓派摄像头读取视频，如何对彩色球进行阈值处理，以及如何在球的顶部放置一个红点。最后，我们使用了树莓派摄像头和超声波传感器来检测球并跟随它。

在下一章中，我们将通过使用 Haar 级联来扩展我们的 OpenCV 知识，检测人脸。之后，我们将识别微笑并让机器人跟随人脸。

# 问题

1.  从图像中分离出一个物体的过程叫什么？

1.  垂直翻转图像的命令是什么？

1.  如果 x>428 且 y>320，红点会在哪个区块？

1.  用于调整摄像头分辨率的命令是什么？

1.  如果物体不在摄像头前方，红点会放在哪里？


# 第八章：使用 Haar 分类器进行面部检测和跟踪

在上一章中，我们编程机器人来检测一个球体并跟随它。在本章中，我们将通过检测和跟踪人脸、检测人眼和识别微笑，将我们的检测技能提升到下一个水平。

在本章中，您将学习以下主题：

+   使用 Haar 级联进行面部检测

+   检测眼睛和微笑

+   面部跟踪机器人

# 技术要求

在本章中，您将需要以下内容：

+   三个 LED 灯

+   一个**树莓派**（RPi）机器人（连接到 RPi 的树莓派摄像头模块）

本章的代码文件可以从[`github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter08`](https://github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter08)下载。

# 使用 Haar 级联进行面部检测

Paul Viola 和 Micheal Jones 在他们的论文《使用增强级联简单特征的快速目标检测》中于 2001 年提出了基于 Haar 特征的级联分类器。Haar 特征的级联分类器是使用面部图像以及非面部图像进行训练的。Haar 级联分类器不仅可以检测正面人脸，还可以检测人的眼睛、嘴巴和鼻子。Haar 特征的分类器也被称为 Viola-Jones 算法。

# Viola-Jones 算法的基本工作

因此，简而言之，Viola-Jones 算法使用 Haar 特征来检测人脸。Haar 通常包括两个主要特征：**边缘特征**和**线特征**。我们将首先了解这两个特征，然后我们将看到这些特征如何用于检测人脸：

+   **边缘特征**：通常用于检测边缘。边缘特征由白色和黑色像素组成。边缘特征可以进一步分为水平边缘特征和垂直边缘特征。在下图中，我们可以看到左侧块上的垂直边缘特征和右侧块上的水平边缘特征：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/16d96ff3-7843-4623-aece-7785b805f5c7.png)

+   **线特征**：通常用于检测线条。在线特征中，一个白色像素被夹在两个黑色像素之间，或者一个黑色像素被夹在两个白色像素之间。在下图中，您可以看到左侧的两个水平线特征，一个在另一个下方，以及右侧的垂直线特征，相邻在一起：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/678d0003-8bce-4105-b5b2-1dfbfeb26524.png)

面部检测始终在灰度图像上执行，但这意味着在灰度图像中，我们可能没有完全黑色和白色的像素。因此，让我们将白色像素称为较亮的像素，黑色像素称为较暗的像素。如果我们看下面的灰度人脸图片，额头区域较亮（较亮的像素）与眉毛区域（较暗的像素）相比：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/1c6d2bdc-a728-45e0-8594-b7b60f82c44d.png)

与眼睛和脸颊区域相比，鼻线区域更亮。同样，如果我们看口部区域，上唇区域较暗，牙齿区域较亮，下唇区域再次较暗：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/086200cb-307d-472a-9aee-79207f357ced.png)

这就是通过使用 Haar 级联的边缘和线特征，我们可以检测人脸中最相关的特征点，如眼睛、鼻子和嘴巴。

OpenCV 4.0 包括不同的预训练 Haar 检测器，可以用于检测人脸，包括眼睛、鼻子、微笑等。在`Opencv-4.0.0`文件夹中，有一个`Data`文件夹，在`Data`文件夹中，您会找到`haarcascades`文件夹。在这个文件夹中，您会找到不同的 Haar 级联分类器。对于正面人脸检测，我们将使用`haarcascade_frontalface_alt2.xml`检测器。在下面的截图中，您可以看到`haarcascades`文件夹的路径，其中包含不同的 Haar 级联分类器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/7defffc4-3716-40fe-8d85-5d5ed6b368c1.png)

现在我们了解了 Viola-Jones 特征的基础知识，我们将编写程序，使我们的机器人使用 Haar 级联检测人脸。

# 人脸检测程序

让我们编写一个程序来检测人脸。我将这个程序命名为`FaceDetection.cpp`，您可以从本书的 GitHub 存储库的`Chapter08`文件夹中下载。

由于我们将使用`haarcascade_frontalface_alt2.xml`来检测人脸，请确保`FaceDetection.cpp`和`haarcascade_frontalface_alt2.xml`文件在同一个文件夹中。

要编写人脸检测程序，请按照以下步骤进行：

1.  在`FaceDetection.cpp`程序中，使用`CascadeClassifier`类加载 Haar 的预训练正面脸 XML，如下面的代码片段所示：

```cpp
CascadeClassifier faceDetector("haarcascade_frontalface_alt2.xml");
```

1.  声明两个矩阵变量，称为`videofeed`和`grayfeed`，以及一个名为`vid(0)`的`VideoCapture`变量，以从 RPi 相机捕获视频：

```cpp
Mat videofeed, grayfeed;
VideoCapture vid(0);
```

1.  在`for`循环内，读取相机视频。然后，水平翻转相机视频。使用`cvtColor`函数，我们可以将我们的`videofeed`转换为`grayscale`。如果您的 Pi 相机放置颠倒，将`flip`函数内的第三个参数设置为`0`。`grayscale`输出存储在`grayfeed`变量中。以下代码显示了如何完成此步骤：

```cpp
vid.read(videofeed);
flip(videofeed, videofeed, 1);
cvtColor(videofeed, grayfeed, COLOR_BGR2GRAY);
```

1.  让我们执行直方图均衡化，以改善`videofeed`的亮度和对比度。直方图均衡化是必需的，因为有时在光线较暗时，相机可能无法检测到人脸。为了执行直方图均衡化，我们将使用`equalizeHist`函数：

```cpp
equalizeHist(grayfeed, grayfeed);
```

1.  让我们检测一些人脸。为此，使用`detectMultiScale`函数，如下所示：

```cpp
detectMultiScale(image, object, scalefactor, min neighbors,flags, min size, max size);
```

在前面的代码片段中显示的`detectMultiScale`函数由以下七个参数组成：

+   +   `image`：表示输入视频源。在我们的情况下，它是`grayfeed`，因为我们将从灰度视频中检测人脸。

+   `object`：表示矩形的向量，其中每个矩形包含检测到的人脸。

+   `scalefactor`：指定图像大小必须缩小多少。比例因子的理想值在 1.1 和 1.3 之间。

+   `flags`：此参数可以设置为`CASCADE_SCALE_IMAGE`、`CASCADE_FIND_BIGGEST_OBJECT`、`CASCADE_DO_ROUGH_SEARCH`或`CASCADE_DO_CANNY_PRUNING`：

+   `CASCADE_SCALE_IMAGE`：这是最流行的标志；它通知分类器，用于检测人脸的 Haar 特征应用于视频或图像。

+   `CASCADE_FIND_BIGGEST_OBJECT`：此标志将告诉分类器在图像或视频中找到最大的脸

+   `CASCADE_DO_ROUGH_SEARCH`：此标志将在检测到人脸后停止分类器。

+   `CASCADE_DO_CANNY_PRUNNING`：此标志通知分类器不要检测锐利的边缘，从而增加检测到人脸的机会。

+   `min neighbors`：最小邻居参数影响检测到的人脸的质量。较高的**最小邻居值**将识别较少的人脸，但无论它检测到什么都一定是人脸。较低的`min neighbors`值可能会识别多个人脸，但有时也可能识别不是人脸的对象。检测人脸的理想`min neighbors`值在 3 和 5 之间。

+   `min size`：最小尺寸参数将检测最小的人脸尺寸。例如，如果我们将最小尺寸设置为 50 x 50 像素，分类器将只检测大于 50 x 50 像素的人脸，忽略小于 50 x 50 像素的人脸。理想情况下，我们可以将最小尺寸设置为 30 x 30 像素。

+   `max size`：最大尺寸参数将检测最大的人脸尺寸。例如，如果我们将最大尺寸设置为 80 x 80 像素，分类器将只检测小于 80 x 80 像素的人脸。因此，如果您离相机太近，您的脸的尺寸超过了最大尺寸，分类器将无法检测到您的脸。

1.  由于`detectMultiScale`函数提供矩形的向量作为其输出，我们必须声明一个`Rect`类型的向量。变量名为`face`。`scalefactor`设置为`1.1`，`min neighbors`设置为`5`，最小比例大小设置为 30 x 30 像素。最大大小在这里被忽略，因为如果您的脸部尺寸变得大于最大尺寸，您的脸部将无法被检测到。要完成此步骤，请使用以下代码：

```cpp
vector<Rect> face;
 faceDetector.detectMultiScale(grayfeed, faces, 1.3, 5, 0 | CASCADE_SCALE_IMAGE, Size(30, 30));
```

检测到脸部后，我们将在检测到的脸部周围创建一个矩形，并在矩形的左上方显示文本，指示“检测到脸部”：

```cpp
for (size_t f = 0; f < face.size(); f++) 
 {
rectangle(videofeed, face[f], Scalar(255, 0, 0), 2);
putText(videofeed, "Face Detected", Point(face[f].x, face[f].y), FONT_HERSHEY_PLAIN, 1.0, Scalar(0, 255, 0), 2.0);
}
```

在`for`循环内，我们使用`face.size()`函数来确定检测到了多少张脸。如果检测到一张脸，`face.size()`等于`1`，`for`循环就会满足条件。在`for`循环内，我们有矩形和`putText`函数。

矩形函数将在检测到的脸部周围创建一个矩形。它由四个参数组成：

+   第一个参数表示我们要在其上绘制矩形的图像或视频源，在我们的例子中是`videofeed`

+   `face[f]`的第二个参数表示我们要在其上绘制矩形的检测到的脸部

+   第三个参数表示矩形的颜色（在此示例中，我们将颜色设置为蓝色）

+   第四个和最后一个参数表示矩形的厚度

`putText`函数用于在图像或视频源中显示文本。它由七个参数组成：

+   第一个参数表示我们要在其上绘制矩形的图像或视频源。

+   第二个参数表示我们要显示的文本消息。

+   第三个参数表示我们希望文本显示的位置。`face[f].x`和`face[f].y`函数表示矩形的左上点，因此文本将显示在矩形的左上方。

+   第四个参数表示字体类型，我们设置为`FONT_HERSHEY_PLAIN`。

+   第五个参数表示文本的字体大小，我们设置为`1`。

+   第六个参数表示文本的颜色，设置为绿色（`Scalar(0,255,0)`）。

+   第七个和最后一个参数表示字体的厚度，设置为`1.0`。

最后，使用`imshow`函数，我们将查看视频源，以及矩形和文本：

```cpp
imshow("Face Detection", videofeed);
```

使用上述代码后，如果您已经编译和构建了程序，您将看到在检测到的脸部周围画了一个矩形：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/aefc64d5-2d06-4ce2-babe-78d97c9a2df2.png)

接下来，我们将检测人眼并识别微笑。一旦眼睛和微笑被识别出来，我们将在它们周围创建圆圈。

# 检测眼睛和微笑

用于检测眼睛和微笑的程序名为`SmilingFace.cpp`，您可以从本书的 GitHub 存储库的`Chapter08`文件夹中下载。

# 检测眼睛

`SmilingFace.cpp`程序基本上是`FaceDetection.cpp`程序的扩展，这意味着我们将首先找到感兴趣的区域，即脸部。接下来，使用 Haar 级联分类器检测眼睛，然后在它们周围画圆圈。

在编写程序之前，让我们首先了解不同的可用的眼睛`CascadeClassifier`。OpenCV 4.0 有三个主要的眼睛级联分类器：

+   `haarcascade_eye.xml`：此分类器将同时检测两只眼睛

+   `haarcascade_lefteye_2splits.xml`：此分类器将仅检测左眼

+   `haarcascade_righteye_2splits.xml`：此分类器将仅检测右眼

根据您的要求，您可以使用`haarcascade_eye`分类器来检测两只眼睛，或者您可以使用`haarcascade_lefteye_2splits`分类器仅检测左眼和`haarcascade_righteye_2splits`分类器仅检测右眼。在`SmilingFace.cpp`程序中，我们将首先使用`haarcascade_eye`分类器测试输出，然后我们将使用`haarcascade_lefteye_2splits`和`haarcascade_righteye_2splits`分类器测试输出。

# 使用`haarcascade_eye`进行眼睛检测

要测试`haarcascade_eye`的输出，观察以下步骤：

1.  在我们的程序中加载这个分类器：

```cpp
CascadeClassifier eyeDetector("haarcascade_eye.xml");
```

1.  要检测眼睛，我们需要在图像（视频源）中找到脸部区域（感兴趣区域）。在脸部检测的`for`循环中，我们将创建一个名为`faceroi`的`Mat`变量。`videofeed(face[f])`，这将在`videofeed`中找到脸部并将它们存储在`faceroi`变量中：

```cpp
Mat faceroi = videofeed(face[f]);
```

1.  创建一个名为`eyes`的`Rect`类型的向量，然后使用`detectMultiScale`函数来检测眼睛区域：

```cpp
vector<Rect> eyes;
eyeDetector.detectMultiScale(faceroi, eyes, 1.3, 5, 0 |CASCADE_SCALE_IMAGE,Size(30, 30));
```

在`detectMultiScale`函数中，第一个参数设置为`faceroi`，这意味着我们只想从脸部区域检测眼睛，而不是从整个视频源检测。检测到的眼睛将存储在 eyes 变量中。

1.  为了在眼睛周围创建圆圈，我们将使用一个`for`循环。让我们找到眼睛的中心。为了找到眼睛的中心，我们将使用`Point`数据类型，并且`eyecenter`变量中的方程将给出眼睛的中心：

```cpp
for (size_t e = 0; e < eyes.size(); e++)
 {
 Point eyecenter(face[f].x + eyes[e].x + eyes[e].width/2, face[f].y + eyes[e].y + eyes[e].height/2);
 int radius = cvRound((eyes[e].width + eyes[e].height)*0.20);
 circle(videofeed, eyecenter, radius, Scalar(0, 0, 255), 2);
 }
```

这的结果可以在这里看到：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/7387dccd-ec92-4337-974e-18bc25e312b4.png)

使用`radius`变量，我们计算了圆的半径，然后使用`circle`函数在眼睛周围创建红色的圆圈。

# 使用`haarcascade_lefteye_2splits`和`haarcascade_righteye_2splits`进行眼睛检测

使用`haarcascade_eye`分类器检测两只眼睛后，让我们尝试仅使用`haarcascade_lefteye_2splits`和`haarcascade_righteye_2splits`分类器分别检测左眼或右眼。

# 检测左眼

要检测左眼，执行以下步骤：

1.  在我们的程序中加载`haarcascade_lefteye_2splits`级联分类器：

```cpp
CascadeClassifier eyeDetectorleft("haarcascade_lefteye_2splits.xml");
```

1.  由于我们想要在脸部区域检测左眼，我们将创建一个名为`faceroi`的`Mat`变量，并在其中存储脸部区域的值：

```cpp
Mat faceroi = videofeed(face[f]);
```

1.  使用`detectMultiScale`函数创建一个名为`lefteye`的`Rect`类型的向量来检测左眼区域。`min neighbors`参数设置为`25`，以便分类器只检测左眼。如果我们将`min neighbors`设置为低于 25，`haarcascade_lefteye_2splits`分类器也可能检测到右眼，这不是我们想要的。要完成此步骤，请使用以下代码：

```cpp
vector<Rect> lefteye;
eyeDetectorleft.detectMultiScale(faceROI, lefteye, 1.3, 25, 0 |CASCADE_SCALE_IMAGE,Size(30, 30));
 for (size_t le = 0; le < lefteye.size(); le++)
 {
 Point center(face[f].x + lefteye[le].x + lefteye[le].width*0.5, face[f].y + lefteye[le].y + lefteye[le].height*0.5);
 int radius = cvRound((lefteye[le].width + lefteye[le].height)*0.20);
 circle(videofeed, center, radius, Scalar(0, 0, 255), 2);
 }
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/e234758b-61ca-4ddd-98c5-48e213cb1c1b.png)

检测左右眼分开的`for`循环代码是`SmilingFace.cpp`程序的一部分，但是被注释掉了。要测试代码，首先注释掉同时检测两只眼睛的`for`循环，然后取消注释检测左眼和右眼的另外两个`for`循环。

# 检测右眼

检测右眼的编程逻辑与检测左眼非常相似。我们唯一需要改变的是分类器名称和一些变量名称，以区分左眼和右眼。要检测右眼，执行以下步骤：

1.  加载`haarcascade_righteye_2splits`级联分类器：

```cpp
CascadeClassifier eyeDetectorright("haarcascade_righteye_2splits.xml");
```

1.  在脸部检测的`for`循环中，找到脸部区域。然后，使用`detectMultiScale`函数来检测右眼。使用`circle`函数在右眼周围创建一个绿色的圆圈。为此，请使用以下代码：

```cpp
Mat faceroi = videofeed(face[f]); 
vector<Rect>  righteye;
eyeDetectorright.detectMultiScale(faceROI, righteye, 1.3, 25, 0 |CASCADE_SCALE_IMAGE,Size(30, 30));

for (size_t re = 0; re < righteye.size(); re++)
 {
 Point center(face[f].x + righteye[re].x + righteye[re].width*0.5, face[f].y + righteye[re].y + righteye[re].height*0.5);
 int radius = cvRound((righteye[re].width + righteye[re].height)*0.20);
 circle(videofeed, center, radius, Scalar(0, 255, 0), 2);
 }
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/89315812-5bdc-45ea-937a-11f6569bd558.png)

如果我们结合左眼和右眼的检测器代码，最终输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/8edd5a4b-37d9-46c4-aad6-cead16da27a1.png)

正如我们所看到的，图片中的左眼被红色圆圈包围，右眼被绿色圆圈包围。

# 识别微笑

在从面部区域检测到眼睛后，让我们编写程序来识别笑脸。当网络摄像头检测到嘴巴周围的黑白黑线特征时，即上下嘴唇通常比牙齿区域略暗时，网络摄像头将识别出一个微笑的脸：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/c969cfe1-1672-4b17-ab75-83ac508ddb17.png)

# 微笑识别的编程逻辑

微笑识别的编程逻辑与眼睛检测类似，我们还将在面部检测的`for`循环内编写微笑识别程序。要编写微笑识别程序，请按照以下步骤进行：

1.  加载微笑`CascadeClassifier`：

```cpp
CascadeClassifier smileDetector("haarcascade_smile.xml");
```

1.  我们需要检测面部区域，它位于面部区域内。面部区域再次是我们的感兴趣区域，为了从视频源中找到面部区域，我们将使用以下命令：

```cpp
Mat faceroi = videofeed(face[f]);
```

1.  声明一个`smile`变量，它是`Rect`类型的向量。然后使用`detectMultiScale`函数。在`detectMultiScale`函数中，将`min neighbors`设置为`25`，以便只有在人微笑时才创建一个圆圈（如果我们将最小邻居设置为低于 25，即使人没有微笑，也可能在嘴周围创建一个圆圈）。您可以在 25-35 之间变化`min neighbors`的值。接下来，在`for`循环内，我们编写了在嘴周围创建绿色圆圈的程序。要完成此步骤，请使用以下代码：

```cpp
vector<Rect> smile; 
smileDetector.detectMultiScale(faceroi, smile, 1.3, 25, 0 |CASCADE_SCALE_IMAGE,Size(30, 30));
 for (size_t sm = 0; sm <smile.size(); sm++)
 {
 Point scenter(face[f].x + smile[sm].x + smile[sm].width*0.5, face[f].y + smile[sm].y + smile[sm].height*0.5);
 int sradius = cvRound((smile[sm].width + smile[sm].height)*0.20);
 circle(videofeed, scenter, sradius, Scalar(0, 255, 0), 2);
 }
```

前面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/785e0ca6-77a7-4e49-b61f-e4ad84056b2e.png)

在接下来的部分中，当检测到眼睛和微笑时，我们将打开不同的 LED。当面部移动时，我们还将使我们的机器人跟随检测到的面部。

# 面部跟踪机器人

用于打开/关闭 LED 和跟踪人脸的程序称为`Facetrackingrobot.cpp`，您可以从本书的 GitHub 存储库的`Chapter08`文件夹中下载。

在`Facetrackingrobot`程序中，我们将首先检测面部，然后是左眼、右眼和微笑。一旦检测到眼睛和微笑，我们将打开/关闭 LED。之后，我们将在面部矩形的中心创建一个小点，然后使用这个点作为移动机器人的参考。

# 接线

对于`Facetrackingrobot`程序，我们至少需要三个 LED：一个用于左眼，一个用于右眼，一个用于微笑识别。这三个 LED 显示在以下图表中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/09d4f5e2-8e71-4b59-a306-e0c8e99fa8a1.png)

LED 和机器人的接线如下：

+   对应**左眼**的左 LED 连接到**wiringPi pin 0**

+   对应**右眼**的右 LED 连接到**wiringPi pin 2**

+   对应**微笑**的中间 LED 连接到**wiringPi pin 3**

+   电机驱动器的**IN1**引脚连接到**wiringPi pin 24**

+   电机驱动器的**IN2**引脚连接到**wiringPi pin 27**

+   电机驱动器的**IN3**引脚连接到**wiringPi pin 25**

+   电机驱动器的**IN4**引脚连接到**wiringPi pin 28**

在我的机器人上，我已经把左右 LED 贴在机器人的顶部底盘上。第三个 LED（中间 LED）贴在机器人的底盘上。我使用绿色 LED 作为眼睛，红色 LED 作为微笑：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/0f5efdb7-3959-47e4-a7e8-cd50dbf74e34.png)

# 编程逻辑

在`Facetrackingrobot`程序中，将 wiringPi 引脚 0、2 和 3 设置为输出引脚：

```cpp
 pinMode(0,OUTPUT);
 pinMode(2,OUTPUT);
 pinMode(3,OUTPUT);
```

从面部检测程序中，您可能已经注意到面部跟踪过程非常缓慢。因此，当您将脸部向左或向右移动时，必须确保电机不要移动得太快。为了减慢电机的速度，我们将使用`softPwm.h`库，这也是我们在第二章中使用的*使用 wiringPi 实现眨眼*：

1.  从`softPwm.h`库中，使用`softPwmCreate`函数声明四个电机引脚（`24`，`27`，`25`和`28`）：

```cpp
softPwmCreate(24,0,100); //pin 24 is left Motor pin
softPwmCreate(27,0,100); //pin 27 is left motor pin 
softPwmCreate(25,0,100); //pin 25 is right motor pin
softPwmCreate(28,0,100); //pin 28 is right motor pin
```

`softPwmCreate`函数中的第一个参数表示 RPi 的 wiringPi 引脚。第二个参数表示我们可以移动电机的最小速度，第三个参数表示我们可以移动电机的最大速度。

1.  加载面部、左眼、右眼和微笑`CascadeClassifiers`：

```cpp
CascadeClassifier faceDetector("haarcascade_frontalface_alt2.xml");
CascadeClassifier eyeDetectorright("haarcascade_righteye_2splits.xml");
CascadeClassifier eyeDetectorleft("haarcascade_lefteye_2splits.xml");
CascadeClassifier smileDetector("haarcascade_smile.xml");
```

1.  在`for`循环内，声明三个布尔变量，称为`lefteyedetect`、`righteyedetect`和`isSmiling`。将这三个变量都设置为`false`。使用这三个变量，我们将检测左眼、右眼和微笑是否被检测到。声明`facex`和`facey`变量，用于找到脸部矩形的中心。要完成此步骤，请使用以下代码：

```cpp
bool lefteyedetect = false;
bool righteyedetect = false;
bool isSmiling = false;
int facex, facey;
```

1.  使用`detectMultiScale`函数检测面部，然后在`for`循环内编写程序创建检测到的面部周围的矩形：

```cpp
vector<Rect> face;
faceDetector.detectMultiScale(grayfeed, face, 1.1, 5, 0 | CASCADE_SCALE_IMAGE,Size(30, 30)); 
 for (size_t f = 0; f < face.size(); f++) 
 {
 rectangle(videofeed, face[f], Scalar(255, 0, 0), 2);

 putText(videofeed, "Face Detected", Point(face[f].x, face[f].y), FONT_HERSHEY_PLAIN, 1.0, Scalar(0, 255, 0), 1.0); 

facex = face[f].x +face[f].width/2;
facey = face[f].y + face[f].height/2; 

Point facecenter(facex, facey);
circle(videofeed,facecenter,5,Scalar(255,255,255),-1);
```

`face[f].x + face[f].width/2`将返回矩形的*x*中心值，`face[f].y + face[f].height/2`将返回矩形的*y*中心值。 *x*中心值存储在`facex`变量中，*y*中心值存储在`facey`变量中。

1.  提供`facex`和`facey`作为`Point`变量的输入，以找到矩形的中心，称为`facecenter`。在圆函数中，使用`facecenter`点变量作为输入，在脸部矩形的中心创建一个点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/47290ac4-3a89-450a-8cce-5b2590f4bd7c.png)

1.  当检测到左眼时，我们将在其周围创建一个红色圆圈，并将`lefteyedetect`变量设置为`true`：

```cpp
eyeDetectorleft.detectMultiScale(faceroi, lefteye, 1.3, 25, 0 |CASCADE_SCALE_IMAGE,Size(30, 30));
 for (size_t le = 0; le < lefteye.size(); le++)
 {
 Point center(face[f].x + lefteye[le].x + lefteye[le].width*0.5, face[f].y + lefteye[le].y + lefteye[le].height*0.5);
 int radius = cvRound((lefteye[le].width + lefteye[le].height)*0.25);
 circle(videofeed, center, radius, Scalar(0, 0, 255), 2);
 lefteyedetect = true;
 }
```

1.  当检测到右眼时，我们将在其周围创建一个浅蓝色圆圈，并将`righteyedetect`变量设置为`true`：

```cpp
 eyeDetectorright.detectMultiScale(faceroi, righteye, 1.3, 25, 0 |CASCADE_SCALE_IMAGE,Size(30, 30));
 for (size_t re = 0; re < righteye.size(); re++)
 {
 Point center(face[f].x + righteye[re].x + righteye[re].width*0.5, face[f].y + righteye[re].y + righteye[re].height*0.5);
 int radius = cvRound((righteye[re].width + righteye[re].height)*0.25);
 circle(videofeed, center, radius, Scalar(255, 255, 0), 2);
 righteyedetect = true;
 }
```

1.  当检测到微笑时，我们将在嘴周围创建一个绿色圆圈，并将`isSmiling`设置为`true`：

```cpp
 smileDetector.detectMultiScale(faceroi, smile, 1.3, 25, 0 |CASCADE_SCALE_IMAGE,Size(30, 30));
 for (size_t sm = 0; sm <smile.size(); sm++)
 {
 Point scenter(face[f].x + smile[sm].x + smile[sm].width*0.5, face[f].y + smile[sm].y + smile[sm].height*0.5);
 int sradius = cvRound((smile[sm].width + smile[sm].height)*0.25);
 circle(videofeed, scenter, sradius, Scalar(0, 255, 0), 2, 8, 0);
 isSmiling = true;
 }
```

在下面的屏幕截图中，您可以看到左眼周围画了一个红色圆圈，右眼周围画了一个浅蓝色圆圈，嘴周围画了一个绿色圆圈，并且在围绕脸部的蓝色矩形的中心有一个白点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/7eeb20e3-f8af-452c-86b4-c69022a3d216.png)

使用三个`if`条件，我们将检查`lefteyedetect`、`righteyedetect`和`isSmiling`变量何时为`true`，并在它们为`true`时打开它们各自的 LED：

+   当检测到左眼时，`lefteyedetect`变量将为`true`。当检测到左眼时，我们将打开连接到 wiringPi 引脚 0 的机器人上的左 LED，如下面的代码所示：

```cpp
if(lefteyedetect == true){
digitalWrite(0,HIGH);
}
else
{
digitalWrite(0,LOW);
}
```

+   当检测到右眼时，`righteyedetect`变量将为`true`。当检测到右眼时，我们将打开连接到 wiringPi 引脚 2 的机器人上的右 LED：

```cpp
if(righteyedetect == true){
digitalWrite(2,HIGH);
}
else
{
digitalWrite(2,LOW);
}
```

+   最后，当识别到微笑时，`isSmiling`变量将为 true。当识别到微笑时，我们将打开连接到 wiringPi 引脚 3 的中间 LED：

```cpp
if(isSmiling == true){
 digitalWrite(3,HIGH);
 }
 else
 {
 digitalWrite(3,LOW);
 }
```

接下来，我们将使用脸部矩形上的白点（点）将机器人向左和向右移动。

# 使用脸部三角形上的白点移动机器人

与第七章类似，*使用 OpenCV 构建一个目标跟踪机器人*，我们将摄像头屏幕分为三个部分：左侧部分、中间部分和右侧部分。当白点位于左侧或右侧部分时，我们将向左或向右转动机器人，从而跟踪脸部。即使我没有调整`videofeed`的大小，`videofeed`的分辨率设置为 640 x 480（宽度为 640，高度为 480）。

您可以根据需要变化范围，但如下图所示，左侧部分设置为 x 范围从 0 到 280，中间部分设置为 280-360 的范围，右侧部分设置为 360 到 640 的范围：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/4fd8cbfd-0afb-421f-841d-bc4db4dbab54.png)

当我们移动我们的脸时，脸部矩形将移动，当脸部矩形移动时，矩形中心的白点也会移动。当点移动时，`facex`和`facey`的值将发生变化。将摄像头屏幕分为三个部分时，我们将使用`facex`变量作为参考，然后我们将使用三个 if 条件来检查白点位于哪个部分。用于比较`facex`值的代码如下：

```cpp
if(facex > 0 && facex < 280)
 {
 putText(videofeed, "Left", Point(320,10), FONT_HERSHEY_PLAIN, 1.0, CV_RGB(0, 0, 255), 2.0); 
 softPwmWrite(24, 0);
 softPwmWrite(27, 30);
 softPwmWrite(25, 30);
 softPwmWrite(28, 0); 
 } 

 if(facex > 360 && facex < 640)
 {
 putText(videofeed, "Right", Point(320,10), FONT_HERSHEY_PLAIN, 1.0, CV_RGB(0, 0, 255), 2.0); 
 softPwmWrite(24, 30);
 softPwmWrite(27, 0);
 softPwmWrite(25, 0);
 softPwmWrite(28, 30);

 }
 if(facex > 280 && facex < 360)
 {
 putText(videofeed, "Middle", Point(320,10), FONT_HERSHEY_PLAIN, 1.0, CV_RGB(0, 0, 255), 2.0); 
 softPwmWrite(24, 0);
 softPwmWrite(27, 0);
 softPwmWrite(25, 0);
 softPwmWrite(28, 0);
 }
```

如果满足第一个`if`条件，这意味着白点位于 0 到 280 之间。在这种情况下，我们在`videofeed`上打印`Left`文本，然后使用`softPwmWrite`函数，使机器人进行轴向左转。在`softPwmWrite`函数内，第一个参数代表引脚号，第二个参数代表我们的电机移动的速度。由于 wiringPi 引脚 24 设置为 0（低），wiringPi 引脚 27 设置为 30，左电机将以 30 的速度向后移动。同样，由于 wiringPi 引脚 25 设置为 30，wiringPi 引脚 28 设置为 0（低），右电机将以 30 的速度向前移动。

30 的速度值在 0 到 100 的范围内，我们在`softPwmCreate`函数中设置。您也可以改变速度值。

如果白点位于 360 到 640 之间，将打印`Right`文本，并且机器人将以 30 的速度进行轴向右转。

最后，当白点位于 280 到 360 之间时，将打印`Middle`文本，机器人将停止移动。

这就是我们如何让机器人跟踪脸部并跟随它。

# 摘要

在本章中，我们使用 Haar 面部分类器从视频源中检测面部，然后在其周围画一个矩形。接下来，我们从给定的面部检测眼睛和微笑，并在眼睛和嘴周围画圈。之后，利用我们对面部、眼睛和微笑检测的知识，当检测到眼睛和微笑时，我们打开和关闭机器人的 LED。最后，通过在脸部矩形中心创建一个白点，我们使机器人跟随我们的脸。

在下一章中，我们将学习如何使用我们的声音控制机器人。我们还将创建一个 Android 应用程序，用于识别我们所说的内容。当 Android 应用程序检测到特定关键词时，Android 智能手机的蓝牙将向树莓派蓝牙发送数据位。一旦我们的机器人识别出这些关键词，我们将使用它们来使机器人朝不同方向移动。

# 问题

1.  我们用于检测面部的分类器的名称是什么？

1.  当我们张开嘴时，会创建哪种类型的特征？

1.  哪个级联可以用于仅检测左眼？

1.  从面部检测眼睛时，该区域通常被称为什么？

1.  `equalizeHist`函数的用途是什么？
