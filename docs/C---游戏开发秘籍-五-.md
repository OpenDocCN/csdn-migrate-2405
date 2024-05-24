# C++ 游戏开发秘籍（五）

> 原文：[`zh.annas-archive.org/md5/260E2BE0C3FA0FF74505C2A10CA40511`](https://zh.annas-archive.org/md5/260E2BE0C3FA0FF74505C2A10CA40511)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：游戏开发中的音频

在本章中，将介绍以下教程：

+   安装 FMOD

+   添加背景音乐

+   添加音效

+   创建音效管理器

+   处理多个音频文件名

# 介绍

游戏开发中最重要的方面之一是音频编程。然而，令人奇怪的是，它也是游戏开发中最被忽视和低估的部分之一。要理解音频在游戏中的影响，可以尝试玩一款带有声音的游戏，比如*反恐精英*或*雷神*，然后再尝试没有声音的游戏。这会产生巨大的影响。如果音频编程没有正确完成，可能会导致游戏崩溃和许多其他问题。

因此，学习正确的音频编程方式非常重要。大多数引擎都会有内置的声音组件。对于其他引擎，我们需要添加音频组件。在本章中，我们将介绍最流行的声音引擎之一。我们还将看看如何将 SDL 集成到我们的 C++代码中，以播放音频和音效。

# 安装 FMOD

开始的第一件事是安装 FMOD。这是最流行的音频引擎之一，几乎所有现代游戏引擎都在使用。它也可以添加到您选择的任何游戏引擎中。另一个流行的音频引擎叫做**Wwise**。这用于集成控制台编程的音频，例如在 PS4 上。

## 准备工作

要完成本教程，您需要一台运行 Windows 的计算机。

## 操作方法…

在本教程中，我们将看到不同类型的源控制可用于我们：

1.  访问[`www.fmod.org/`](http://www.fmod.org/)。

1.  要下载 FMOD，请访问[`www.fmod.org/download/`](http://www.fmod.org/download/)。

有一个编辑音频文件的创作工具。但是，我们应该下载 FMOD Studio 程序员 API 和低级程序员 API。

它还为所有现代引擎提供插件，如 Cocos2d-x、Unreal Engine 和 Unity3D。

## 工作原理…

FMOD 是一个低级 API，因此它提供了回调，帮助我们使用 FMOD 的接口来播放声音，暂停声音，以及执行许多其他操作。因为我们有源文件，我们可以构建库并在我们自己的引擎中使用它。FMOD 还为 Unity3D 提供了 API，这意味着代码也暴露给 C#，使其在 Unity3D 中更容易使用。

# 添加背景音乐

如果游戏没有背景音乐，就会显得不完整。因此，非常重要的是我们将播放音乐的方式集成到我们的 C++引擎中。有各种各样的方法可以做到这一点。我们将使用 SDL 在游戏中播放音乐。

## 准备工作

您需要一台运行 Windows 的计算机和一个可用的 Visual Studio 副本。还需要 SDL 库。

## 操作方法…

在本教程中，我们将了解播放背景音乐有多容易：

1.  添加一个名为`Source.cpp`的源文件。

1.  将以下代码添加到其中：

```cpp
#include <iostream>
#include "../AudioDataHandler.h"

#include "../lib/SDL2/include/SDL2/SDL.h"

#include "iaudiodevice.hpp"
#include "iaudiocontext.hpp"
#include "audioobject.hpp"

#include "sdl/sdlaudiodevice.hpp"
#include "sdl/sdlaudiocontext.hpp"

#define FILE_PATH "./res/audio/testClip.wav"

int main(int argc, char** argv)
{
  SDL_Init(SDL_INIT_AUDIO);

  IAudioDevice* device = new SDLAudioDevice();
  IAudioContext* context = new SDLAudioContext();

  IAudioData* data = device->CreateAudioFromFile(FILE_PATH);

  SampleInfo info;
  info.volume = 1.0;
  info.pitch = 0.7298149802137;

  AudioObject sound(info, data);
  sound.SetPos(0.0);

  char in = 0;
  while(in != 'q')
  {
    std::cin >> in;
    switch(in)
    {
      case 'a':
        context->PlayAudio(sound);
        break;
      case 's':
        context->PauseAudio(sound);
        break;
      case 'd':
        context->StopAudio(sound);
        break;
    }
  }

  device->ReleaseAudio(data);
  delete context;
  delete device;

  SDL_Quit();
  return 0;
}

int main()
{
  AudioDataHandler _audioData;
  cout<<_audioData.GetAudio(AudioDataHandler::BACKGROUND);
}
```

## 工作原理…

在这个例子中，我们正在为我们的游戏播放背景音乐。我们需要创建一个接口作为现有 SDL 音频库的包装器。接口还可以提供一个基类以便将来派生。我们需要`SDLAudioDevice`，这是播放音乐的主处理对象。除此之外，我们还创建了一个指向音频数据对象的指针，它可以从提供的文件路径创建音频。设备处理对象有一个内置函数叫做`CreateAudioFromFile`，可以帮助我们完成这个过程。最后，我们有一个音频上下文类，它有播放、暂停和停止音频的功能。每个函数都以音频对象作为引用，用于对我们的音频文件执行操作。

# 添加音效

音效是向游戏添加一些紧张感或成就感的好方法。播放、暂停和停止音效的操作方式与我们在上一个示例中看到的背景音乐相同。然而，我们可以通过控制它们的位置、音量和音调来为声音文件增加一些变化。

## 准备工作

你需要一台正常工作的 Windows 机器。

## 如何做…

添加一个名为`Source.cpp`的源文件，并将以下代码添加到其中：

```cpp
struct SampleInfo
{
  double volume;
  double pitch;
};

SampleInfo info;
info.volume = 1.0;
info.pitch = 0.7298149802137;

AudioObject sound(info, data);
sound.SetPos(0.0);
```

## 它是如何工作的…

在这个示例中，我们只关注游戏中涉及修改声音文件音调、音量和位置的部分。这三个属性可以被视为声音文件的属性，但还有其他属性。因此，首先要做的是创建一个结构。结构用于存储声音的所有属性。我们只需要在需要时填充结构的值。最后，我们创建一个音频对象，并将`SampleInfo`结构作为对象的参数之一传递进去。构造函数然后初始化声音具有这些属性。因为我们将属性附加到对象上，这意味着我们也可以在运行时操纵它们，并在需要时动态降低音量。音调和其他属性也可以以同样的方式进行操纵。

# 创建音效管理器

尽管不是最佳实践之一，但处理音频的最常见方法之一是创建一个管理器类。管理器类应确保整个游戏中只有一个音频组件，控制要播放、暂停、循环等哪种声音。虽然有其他编写管理器类的方法，但这是最标准的做法。

## 准备工作

对于这个示例，你需要一台 Windows 机器和 Visual Studio。

## 如何做…

在这个示例中，我们将了解如何使用以下代码片段轻松添加音效管理器：

```cpp
#pragma once
#include <iostream>
#include "../lib/SDL2/include/SDL2/SDL.h"

#include "iaudiodevice.hpp"
#include "iaudiocontext.hpp"
#include "audioobject.hpp"

#include "sdl/sdlaudiodevice.hpp"
#include "sdl/sdlaudiocontext.hpp"

#define FILE_PATH "./res/audio/testClip.wav"

class GlobalAudioClass
{
private:

  AudioObject* _audObj;
  IAudioDevice* device = new SDLAudioDevice();
  IAudioContext* context = new SDLAudioContext();

  IAudioData* data = device->CreateAudioFromFile(FILE_PATH);

  SampleInfo info;

  static GlobalAudioClass *s_instance;

  GlobalAudioClass()
  {
    info.volume = 1.0;
   info.pitch = 0.7298149802137;
    _audObj = new AudioObject(info,data);
  }
  ~GlobalAudioClass()
  {
    //Delete all the pointers here
  }
public:
  AudioObject* get_value()
  {
    return _audObj;
  }
  void set_value(AudioObject* obj)
  {
    _audObj = obj;
  }
  static GlobalAudioClass *instance()
  {
    if (!s_instance)
      s_instance = new GlobalAudioClass();
    return s_instance;
  }
};

// Allocating and initializing GlobalAudioClass's
// static data member.  The pointer is being
// allocated - not the object inself.
GlobalAudioClass *GlobalAudioClass::s_instance = 0;
```

## 它是如何工作的…

在这个示例中，我们编写了一个单例类来实现音频管理器。单例类具有所有必要的`sdl`头文件和其他播放声音所需的设备和上下文对象。所有这些都是私有的，因此无法从其他类中访问。我们还创建了一个指向该类的静态指针，并将构造函数也设为私有。如果我们需要这个音频管理器的实例，我们必须使用静态的`GlobalAudioClass *instance()`函数。该函数会自动检查是否已经创建了一个实例，然后返回该实例，或者创建一个新的实例。因此，管理器类始终只存在一个实例。我们还可以使用管理器来设置和获取声音文件的数据，例如设置声音文件的路径。

# 处理多个声音文件名称

在游戏中，不会只有一个声音文件，而是多个声音文件需要处理。每个文件都有不同的名称、类型和位置。因此，单独定义所有这些并不明智。虽然这样做可以工作，但如果游戏中有超过 20 个音效，那么编码将会非常混乱，因此需要对代码进行轻微改进。

## 准备工作

在这个示例中，你需要一台 Windows 机器和安装了 SVN 客户端的版本化项目。

## 如何做…

在这个示例中，你将看到处理多个声音文件名称有多么容易。你只需要添加一个名为`Source.cpp`的源文件。将以下代码添加到其中：

```cpp
#pragma once

#include <string>
using namespace std;

class AudioDataHandler
{
public:
  AudioDataHandler();
  ~AudioDataHandler();
  string GetAudio(int data) // Set one of the enum values here from the driver program
  {
    return Files[data];
  }

  enum AUDIO
  {
    NONE=0,
    BACKGROUND,
    BATTLE,
    UI
  };
private:
  string Files[] =
  {
    "",
    "Hello.wav",
    "Battlenn.wav",
    "Click.wav"
  }

};

int main()
{
  AudioDataHandler _audioData;
  cout<<_audioData.GetAudio(AudioDataHandler::BACKGROUND);
}
```

## 它是如何工作的…

在这个例子中，我们创建了一个音频数据处理类。该类有一个`enum`，其中存储了所有声音的逻辑名称，例如`battle_music`，`background_music`等。我们还有一个字符串数组，其中存储了声音文件的实际名称。顺序很重要，它必须与我们编写的`enum`的顺序相匹配。现在这个`enum`被创建了，我们可以创建这个类的对象，并设置和获取音频文件名。`enum`被存储为整数，并默认从`0`开始，名称作为字符串数组的索引。所以`Files[AudioDataHandler::Background]`实际上是`Files[1]`，即`Hello.wav`，因此将播放正确的文件。这是一种非常整洁的组织音频数据文件的方式。在游戏中处理音频的另一种方式是在 XML 或 JSON 文件中具有音频文件的名称和其位置的属性，并有一个读取器解析这些信息，然后以与我们相同的方式填充数组。这样，代码就变得非常数据驱动，因为设计师或音频工程师可以只更改 XML 或 JSON 文件的值，而无需对代码进行任何更改。


# 第十三章：技巧和窍门

在本章中，将涵盖以下步骤：

+   有效地注释你的代码

+   在结构中使用位字段

+   编写健全的技术设计文档

+   使用 const 关键字优化你的代码

+   在枚举中使用位移运算符

+   在 C++11 中使用新的 lambda 特性

# 介绍

C++是一个广阔的海洋。掌握 C++需要许多概念和技巧。此外，程序员还可以不时学习一些小技巧，以帮助开发更好的软件。在本章中，我们将看一些程序员可以学习的技术。

# 有效地注释你的代码

程序员往往在解决问题时如此专注，以至于忘记注释他们的代码。虽然当他们在工作时这可能不是问题，但如果有其他团队成员参与，他们必须使用相同的代码部分，那么理解起来可能会变得非常困难。因此，从开发的早期阶段就注释代码是至关重要的。

## 准备工作

要完成这个步骤，你需要一台运行 Windows 和 Visual Studio 的机器。不需要其他先决条件。

## 如何做...

在这个步骤中，我们将看到注释代码是多么容易。让我们添加一个名为`Source.cpp`的源文件。将以下代码添加到文件中：

```cpp
//Header files
#include <iostream>

class Game
{
  //Member variables (Already known)
public:
private:
protected:

};

//Adding 2 numbers
int Add(int a=4,int b=5)
{
  return a + b;
}

void Logic(int a,int b)
{
  if (a > 10 ? std::cout << a : std::cout << b);

}
int main()
{
  std::cout<<Add()<<std::endl;
  Logic(5,8);

  int a;
  std::cin >> a;
}
```

## 它是如何工作的...

注释应该写在任何部分，以帮助其他开发人员理解发生了什么。要注释代码，我们使用`//`双斜杠符号。我们在其中写的任何内容都不会被编译器编译，也会被忽略。因此，我们可以用它来备注代码中的不同方面。我们还可以使用`/*`和`*/`符号来注释多行。在`/*`和`*/`符号之间的任何内容都将被编译器忽略。如果我们需要调试应用程序，这种技术就会变得有用。我们首先注释掉我们认为是罪魁祸首的大部分代码。现在代码应该可以构建。然后我们开始取消注释代码，直到我们再次达到代码中断的地方。

有时程序员倾向于过度注释。例如，在加法函数的顶部写`//Addition`是没有必要的，因为我们可以清楚地看到正在添加两个数字。同样，我们也不应该少加注释。因为在`Logic`函数的顶部没有注释，我们不知道为什么要使用该函数以及该函数的作用。因此，我们必须记住适度添加注释。这只有通过实践和在团队环境中工作才能实现。

# 在结构中使用位字段

在结构中，我们可以使用位字段来表示我们希望结构的大小是多少。除此之外，了解结构实际占用的大小也很重要。

## 准备工作

你需要一台运行 Windows 的机器和一个可用的 Visual Studio 副本。不需要其他先决条件。

## 如何做...

在这个步骤中，我们将发现使用位字段来找到结构的大小是多么容易。添加一个名为`Source.cpp`的源文件。然后将以下代码添加到其中：

```cpp
#include <iostream>

struct Type
{
  int a;
  unsigned char c[9];
  unsigned  b;
  float d;

};

struct Type2
{
  int a : 2;
  int b : 2;
};
int main()
{
  std::cout << sizeof(Type)<<std::endl;
  std::cout << sizeof(Type2);

  int a;
  std::cin >> a;
}
```

## 它是如何工作的...

正如你所看到的，在这个例子中，我们分配了一个 int 的结构体，一个 char 数组，一个未定义的无符号变量和一个浮点数。当我们执行程序时，输出应该是两个结构体的字节数。假设我们在 64 位机器上运行这个程序，int 是 4 字节，无符号 char 数组是 9 字节，默认情况下无符号是 4 字节，浮点数是 4 字节。如果我们把它们加起来，总共是 21 字节。但如果我们打印出来，我们会注意到输出是 24 字节。这是由于*填充*。C++总是以 4 字节的块获取数据。因此，它会一直填充额外的字节，直到大小是 4 的倍数。因为结构的大小是 21，最接近的 4 的倍数是 24，所以我们得到了那个答案。填充不是针对整个结构的，而是针对每个声明，例如：

```cpp
struct structA
{
   char a;
   char b;
   char c;
   int d;
};

struct structB
{
   char a;
   int d;
   char b;
   char c;
};

Sizeof structA = 2 bytes
Sizeof structb = 3 bytes
```

看看第二个结构，我们所做的是分配了一个位字段。尽管 int 是 4 个字节，我们可以指示它只有 2 个字节。做法是在字节值后面加上一个`:`符号。因此，对于第二个结构，如果我们找到该值，它将输出为`4`而不是`8`。

# 编写完善的技术设计文档

当我们启动一个项目时，通常会依赖两个文档。第一个文档是游戏设计文档，第二个是技术设计文档。技术设计文档应列出关键特性和关键特性的高级架构。然而，随着独立游戏的出现，这个系统正在迅速改变。但是，在大型游戏工作室中，这个流程仍然有效。

## 准备工作

您需要一个可用的 Windows 机器。

## 如何做…

在这个示例中，我们将看到创建技术设计文档有多么容易：

1.  打开您选择的编辑器，最好是 Microsoft Word。

1.  列出游戏的关键技术组件。

1.  创建数据流图来表示引擎各个组件之间的数据流。

1.  创建流程图以解释某个复杂部分的逻辑。

1.  为游戏开发关键部分编写伪代码。

## 它是如何工作的…

一旦列出了关键组件，项目经理就可以自动评估每个任务的风险和复杂性。开发人员也将了解引擎或游戏的关键组件是什么。这也将帮助开发人员计划他们的行动。制作数据流图后，将很容易理解哪个组件依赖于哪个其他组件。因此，开发人员将知道他们必须在开始编码*B*之前实现*A*。流程图也是了解逻辑流程的好方法，有时有助于解决未来可能出现的歧义。最后，伪代码对于向开发人员解释他们必须如何实现代码或者说什么是一个可取的方法是至关重要的。由于伪代码与语言无关，因此即使在 C++之外的其他语言中编写游戏，也可以使用相同的伪代码。

# 使用 const 关键字优化您的代码

我们已经在之前的示例中看到`const`关键字用于使数据或指针常量，以便我们无法更改值或地址。使用`const`关键字还有一个优点。这在面向对象的范式中特别有用。

## 准备工作

对于这个示例，您将需要一个 Windows 机器和安装了 Visual Studio 的版本。

## 如何做…

在这个示例中，我们将发现如何有效地使用`const`关键字有多么容易：

```cpp
#include <iostream>

class A
{
public:

  void Calc()const
  {
    Add(a, b);
    //a = 9;       // Not Allowed
  }
  A()
  {
    a = 10;
    b = 10;

  }
private:

  int a, b;
  void Add(int a, int b)const
  {

    std::cout << a + b << std::endl;
  }
};

int main()
{

  A _a;
  _a.Calc();

  int a;
  std::cin >> a;

  return 0;
}
```

## 它是如何工作的…

在这个示例中，我们正在编写一个简单的应用程序来添加两个数字。第一个函数是一个公共函数。这意味着它对其他类是可见的。每当我们编写公共函数时，我们必须确保它们不会损害该类的任何私有数据。例如，如果公共函数要返回成员变量的值或更改值，那么这个公共函数就非常危险。因此，我们必须确保该函数不能通过在函数末尾添加`const`关键字来修改任何成员变量。这确保了该函数不允许更改任何成员变量。如果我们尝试为成员变量分配不同的值，我们将收到编译器错误：

```cpp
error C3490: 'a' cannot be modified because it is being accessed through a const object.
```

因此，这使得代码更加安全。然而，还有另一个问题。这个公共函数内部调用另一个私有函数。如果这个私有函数修改了成员变量的值会怎么样？同样，我们将面临相同的风险。因此，C++不允许我们调用该函数，除非它在函数末尾具有相同的 const 签名。这是为了确保该函数不能更改成员变量的值。

# 在枚举中使用位移操作符

正如我们之前在之前的示例中看到的，枚举用于表示一组状态。所有状态默认情况下都被赋予一个整数值，从`0`开始。但是，我们也可以指定不同的整数值。更有趣的是，我们可以使用位移操作符来组合一些状态，轻松地将它们设置为活动或非活动状态，并对它们进行其他操作。

## 准备工作

要完成这个示例，您需要一台安装了 Visual Studio 的 Windows 机器。

## 如何做…

在这个示例中，我们将看到在枚举中编写位移操作符是多么容易：

```cpp
#include <iostream>

enum Flags
{
  FLAG1 = (1 << 0),
  FLAG2 = (1 << 1),
  FLAG3 = (1 << 2)
};

int main()
{

  int flags = FLAG1 | FLAG2;

  if (flags&FLAG1)
  {
    //Do Something
  }
  if (flags&FLAG2)
  {
    //Do Something
  }

  return 0;
}
```

## 它是如何工作的…

在上面的示例中，枚举中有三个标志状态。它们由位移操作符表示。因此，在内存中，第一个状态表示为`0000`，第二个状态表示为`0001`，第三个状态表示为`0010`。现在我们可以使用`OR`运算符（`|`）组合这些状态。我们可以有一个名为`JUMP`的状态和另一个名为`SHOOT`的状态。如果我们现在希望角色同时`JUMP`和`SHOOT`，我们可以组合这些状态。我们可以使用`&`运算符来检查状态是否处于活动状态。类似地，如果我们需要从组合中移除一个状态，我们可以使用`XOR`运算符（`^`）。我们可以使用`~`运算符来禁用一个状态。

# 使用 C++ 11 的新 lambda 函数

Lambda 函数是 C++家族的新成员。它们可以被描述为匿名函数。

## 准备工作

要完成这个示例，您需要一台运行 Windows 和 Visual Studio 的机器。

## 如何做…

为了理解 lambda 函数，让我们看一下下面的代码：

```cpp
#include <iostream>
#include <algorithm>
#include <vector>
using namespace std;

int main()
{
  vector<int> numbers{ 4,8,9,9,77,8,11,2,7 };
  int b = 10;
  for_each(numbers.begin(), numbers.end(), = mutable->void { if(y>b) cout<<  y<<endl;  });

  int a;
  cin >> a;

}
```

## 它是如何工作的…

Lambda 函数是 C++11 家族的新成员。它们是匿名函数，非常方便。它们通常作为参数传递给函数。lambda 函数的语法如下：

+   `[捕获列表]（参数）mutable（可选）异常属性-> ret {主体}`

`mutable`关键字是可选的，用于修改参数并调用它们的非 const 函数。属性提供了闭包类型的规范。捕获列表是可选的，并且有一个允许的类型列表：

+   `[a，＆b]`：这里`a`按值捕获，`b`按引用捕获

+   `[this]`：这通过值捕获`this`指针

+   `[＆]`：这通过引用捕获 lambda 主体中使用的所有自动变量

+   `[=]`：这通过值捕获 lambda 主体中使用的所有自动变量

+   `[]`：这不捕获任何东西

Params 是参数列表，就像命名函数一样，只是不允许默认参数（直到 C++14）。如果 auto 被用作参数的类型，lambda 就是一个通用 lambda（自 C++14 以来）。`ret`是函数的返回类型。如果没有提供类型，那么`ret`会尝试自动注入返回类型，如果没有返回任何东西，则为 void。最后，我们有函数的主体，用于编写函数的逻辑。

在这个示例中，我们存储了一个数字列表的向量。之后，我们遍历列表并使用 lambda 函数。lambda 函数存储所有大于 10 的数字并显示数字。lambda 函数可能很难开始，但是练习后，它们很容易掌握。
