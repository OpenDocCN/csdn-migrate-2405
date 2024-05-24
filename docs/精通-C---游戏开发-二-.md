# 精通 C++ 游戏开发（二）

> 原文：[`annas-archive.org/md5/C9DEE6A3AC368562ED493911597C48C0`](https://annas-archive.org/md5/C9DEE6A3AC368562ED493911597C48C0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：构建资产流水线

游戏本质上是以有趣和引人入胜的方式打包的资产或内容的集合。处理视频游戏所需的所有内容本身就是一个巨大的挑战。在任何真正的项目中，都需要一个结构来导入、转换和使用这些资产。在本章中，我们将探讨开发和实施资产流水线的主题。以下是我们将要涵盖的主题：

+   处理音频

+   处理图像

+   导入模型网格

# 什么是资产流水线？

在第三章中，*构建坚实的基础*，我们看了一下如何使用辅助和管理类的结构，将多个方法封装成易于消费的接口，以处理项目的各个部分。在接下来的几节中，我们将使用这些技术来构建我们自己的自定义框架/内容流水线。

# 处理音频

为了开始，我们将通过查看如何处理游戏项目中的音频资产来逐步进入这个过程。为了帮助我们进行这个过程，我们将再次使用一个辅助库。有数百种不同的库可以帮助使用音频。以下是一些较受欢迎的选择：

+   FMOD ([`www.fmod.org`](http://www.fmod.org/))

+   Wwise ([`www.audiokinetic.com/products/wwise/`](https://www.audiokinetic.com/products/wwise/))

+   XAudio2 ([`msdn.microsoft.com/en-us/library/windows/desktop/ee415813(v=vs.85).aspx`](https://msdn.microsoft.com/en-us/library/windows/desktop/ee415813(v=vs.85).aspx))

+   OpenAL ([`www.openal.org/`](https://www.openal.org/))

+   SDL_mixer ([`www.libsdl.org/projects/SDL_mixer/`](https://www.libsdl.org/projects/SDL_mixer/))

每个库都有其自身的优势和劣势。为您的项目选择合适的库归结为您应该问自己的几个不同问题。

这个库是否满足你的技术需求？它是否具有你想要的所有功能？

它是否符合项目的预算限制？许多更强大的库都有很高的价格标签。

这个库的学习曲线是否在你或团队的技能范围内？选择一个带有许多酷炫功能的高级 API 可能看起来是个好主意，但如果你花费更多时间来理解 API 而不是实施它，那可能是有害的。

在本书的示例中，我选择使用`SDL_mixer API`有几个原因。首先，与其他一些库相比，它相对容易上手。其次，它非常符合我的项目需求。它支持 FLAC、MP3，甚至 Ogg Vorbis 文件。第三，它与项目框架的其余部分连接良好，因为它是 SDL 库的扩展，而我们已经在使用。最后，我选择这个 API 是因为它是开源的，而且有一个简单的许可证，不需要我支付创建者我的游戏收益的一部分来使用该库。

让我们首先看一下我们需要的几个不同类的声明和实现。我们要看的文件是`AudioManager.h`文件，可以在代码库的`Chapter04`文件夹中找到。

我们从必要的包含开始，`SDL/SDL_mixer.h`，`string`和`map`的实现。与所有其他引擎组件一样，我们将这些声明封装在`BookEngine`命名空间中：

```cpp
#pragma once 
#include <SDL/SDL_mixer.h> 
#include <string> 
#include <map> 

namespace BookEngine 
{
```

在`"AudioManager.h"`文件中，我们声明了一些辅助类。第一个是`SoundEffect`类。这个类定义了游戏中要使用的音效对象的结构：

```cpp
class SoundEffect 
 { 
  public: 
    friend class AudioManager; 
    ///Plays the sound file 
    ///@param numOfLoops: If == -1, loop forever, 
    ///otherwise loop of number times provided + 1 
    void Play(int numOfLoops = 0); 

  private: 
    Mix_Chunk* m_chunk = nullptr; 
  }; 
```

这些可以包括玩家跳跃、武器开火等声音，以及我们将在短暂时间内播放的任何声音。

在类定义内部，我们需要一个`friend`类语句，允许这个类访问`AudioManager`类的方法和变量，包括私有的。接下来是`Play`函数的定义。这个函数将简单地播放音效，并只接受一个参数，循环播放声音的次数。默认情况下，我们将其设置为`0`，如果您将循环次数设置为`-1`，它将无限循环播放音效。最后一个定义是一个`Mix_Chunk`类型的私有变量。`Mix_Chunk`是一个`SDL_mixer`对象类型，它在内存中存储音频数据。

`Mix_Chunk`对象的结构如下：

```cpp
typedef struct { 
        int allocated; 
        Uint8 *abuf; 
        Uint32 alen; 
        Uint8 volume; 
} Mix_Chunk; 
```

这是对象的内部：

+   `allocated`：如果设置为`1`，`struct`有自己的分配缓冲区

+   `abuf`：这是指向音频数据的指针

+   `alen`：这是音频数据的长度，以字节为单位

+   `volume`：这是每个样本的音量值，介于 0 和 128 之间

我们在`AudioManager.h`文件中的下一个辅助类是`Music`类。像音效一样，`Music`类定义了`Music`对象的结构。这可以用于像加载屏幕音乐、背景音乐和任何我们希望长时间播放或需要停止、开始和暂停的声音：

```cpp
class Music 
  { 
  public: 
    friend class AudioManager; 
    ///Plays the music file 
    ///@param numOfLoops: If == -1, loop forever, 
    ///otherwise loop of number times provided 
    void Play(int numOfLoops = -1); 

    static void Pause() { Mix_PauseMusic(); }; 
    static void Stop() { Mix_HaltMusic(); }; 
    static void Resume() { Mix_ResumeMusic(); }; 

  private: 
    Mix_Music* m_music = nullptr; 
  }; 
```

对于类定义，我们再次从一个`friend`类语句开始，以便`Music`类可以访问`AudioManager`类的所需部分。接下来是一个`Play`函数，就像`SoundEffect`类一样，它接受一个参数来设置声音循环的次数。在`Play`函数之后，我们有另外三个函数，`Pause()`、`Stop()`和`Resume()`函数。这三个函数只是对底层 SDL_mixer API 调用的包装，用于暂停、停止和恢复音乐。

最后，我们有一个`Mix_Music`对象的私有声明。`Mix_Music`是用于音乐数据的 SDL_mixer 数据类型。它支持加载 WAV、MOD、MID、OGG 和 MP3 音频文件。我们将在接下来的实现部分中了解更多关于这个的信息：

```cpp
class AudioManager 
  { 
  public: 
    AudioManager(); 
    ~AudioManager(); 

    void Init(); 
    void Destroy(); 

    SoundEffect LoadSoundEffect(const std::string& filePath); 
    Music LoadMusicEffect(const std::string& filePath); 
  private: 
    std::map<std::string, Mix_Chunk*> m_effectList; 
    std::map<std::string, Mix_Music*> m_musicList; 
    bool m_isInitialized = false; 
  }; 
} 
```

在两个`Music`和`SoundEffect`辅助类之后，我们现在来到`AudioManager`类的定义。`AudioManager`类将在我们这一边承担大部分繁重的工作，它将加载、保存和管理所有音乐和音效的创建和删除。

我们的类声明像大多数其他类一样以默认构造函数和析构函数开始。接下来是一个`Init()`函数。这个函数将处理音频系统的设置或初始化。然后是一个`Destroy()`函数，它将处理音频系统的删除和清理。在`Init`和`Destroy`函数之后，我们有两个加载函数，`LoadSoundEffect()`和`LoadMusicEffent()`函数。这两个函数都接受一个参数，一个标准字符串，其中包含音频文件的路径。这些函数将加载音频文件，并根据函数返回`SoundEffect`或`Music`对象。

我们的类的私有部分有三个对象。前两个私有对象是`Mix_Chunk`或`Mix_Music`类型的映射。这是我们将存储所有需要的效果和音乐的地方。通过存储我们加载的音效和音乐文件列表，我们创建了一个缓存。如果在项目的以后时间需要文件，我们可以检查这些列表并节省一些宝贵的加载时间。最后一个变量`m_isInitialized`保存一个布尔值，指定`AudioManager`类是否已经初始化。

这完成了`AudioManager`和辅助类的声明，让我们继续实现，我们可以更仔细地查看一些函数。您可以在代码存储库的`Chapter04`文件夹中找到`AudioManager.cpp`文件：

```cpp
#include "AudioManager.h"
#include "Exception.h" 
#include "Logger.h"

namespace BookEngine 
{ 

  AudioManager::AudioManager() 
  { 
  } 

  AudioManager::~AudioManager() 
  { 
    Destroy(); 
  } 
```

我们的实现从包括、默认构造函数和析构函数开始。这里没有什么新东西，唯一值得注意的是我们从析构函数中调用`Destroy()`函数。这允许我们通过析构函数或通过显式调用对象本身的`Destroy()`函数来清理类的两种方法：

```cpp
void BookEngine::AudioManager::Init() 
  { 
    //Check if we have already been initialized 
    if (m_isInitialized) 
      throw Exception("Audio manager is already initialized"); 
```

`AudioManager`类实现中的下一个函数是`Init()`函数。这是设置管理器所需组件的函数。函数开始时进行简单检查，看看我们是否已经初始化了该类；如果是，我们会抛出一个带有调试消息的异常：

```cpp
//Can be Bitwise combination of  
//MIX_INIT_FAC, MIX_INIT_MOD, MIX_INIT_MP3, MIX_INIT_OGG 
if(Mix_Init(MIX_INIT_OGG || MIX_INIT_MP3) == -1) 
 throw Exception("SDL_Mixer could not initialize! Error: " + 
 std::string(Mix_GetError()));
```

在检查我们是否已经这样做之后，我们继续初始化 SDL_mixer 对象。我们通过调用`Mix_Init()`函数并传入一组标志的位组合来实现这一点，以设置支持的文件类型。这可以是 FLAC、MOD、MP3 和 OGG 的组合。在这个例子中，我们传递了 OGG 和 MP3 支持的标志。我们将这个调用包装在一个 if 语句中，以检查`Mix_Init()`函数调用是否有任何问题。如果遇到错误，我们会抛出另一个带有从`Mix_Init()`函数返回的错误信息的调试消息的异常：

```cpp
if(Mix_OpenAudio(MIX_DEFAULT_FREQUENCY, MIX_DEFAULT_FORMAT, 2, 
 1024) == -1)      throw Exception("Mix_OpenAudio Error: " + 
 std::string(Mix_GetError()));
```

一旦`SDL_mixer`函数被初始化，我们就可以调用`Mix_OpenAudio`来配置要使用的`frequency`、`format`、`channels`和`chunksize`。重要的是要注意，这个函数必须在任何其他`SDL_mixer`函数之前调用。函数定义如下：

```cpp
int Mix_OpenAudio(int frequency, Uint16 format, int channels, int chunksize)
```

以下是参数的含义：

+   `frequency`：这是每秒采样的输出频率，以赫兹为单位。在示例中，我们使用`MIX_DEFAULT_FREQUENCY`定义，即 22050，这是大多数情况下的一个很好的值。

+   `format`：这是输出样本格式；同样，在示例中，我们将其设置为默认值，使用`MIX_DEFAULT_FORMAT`定义，这与使用`AUDIO_S16SYS`或有符号 16 位样本，系统字节顺序相同。要查看完整的格式定义列表，请参见`SDL_audio.h`文件。

+   `channels`：这是输出中的声道数。立体声为 2 声道，单声道为 1 声道。我们的示例中使用值 2。

+   `chunksize`：这是每个输出样本使用的字节数。我们使用`1024`字节或 1 兆字节（mb）作为我们的 chunksize。

最后，在这个函数中我们做的最后一件事是将`m_isInitalized`布尔值设置为 true。这将阻止我们意外地尝试再次初始化该类：

```cpp
m_isInitialized = true; 
  } 
```

`AudioManager`类中的下一个函数是`Destroy()`方法：

```cpp
  void BookEngine::AudioManager::Destroy() 
  { 
    if (m_isInitialized) 
    { 
      m_isInitialized = false; 

      //Release the audio resources 
      for(auto& iter : m_effectList) 
        Mix_FreeChunk(iter.second); 
      for(auto& iter : m_musicList) 
        Mix_FreeMusic(iter.second); 
      Mix_CloseAudio(); 
      Mix_Quit(); 
    } 
  } 
```

我不会逐行讲解这个函数，因为它是不言自明的。基本概述是：检查`AudioManager`是否已经初始化，如果是，则使用`Mix_FreeChunk()`函数释放我们创建的每个声音和音乐资源。最后，我们使用`Mix_CloseAudio()`和`Mix_Quit()`来关闭、清理和关闭 SDL_mixer API。

`LoadSoundEffect`是我们需要查看的下一个函数。这个函数就像它的名字所暗示的那样，是加载音效的函数：

```cpp
 SoundEffect BookEngine::AudioManager::LoadSoundEffect(const std::string & filePath)
  { 
    SoundEffect effect; 
```

这个函数的第一步是创建一个`SoundEffect`对象，临时保存数据，直到我们将效果返回给调用方法。我们简单地称这个变量为 effect。

创建了我们的临时变量后，我们快速检查一下我们需要的这个效果是否已经被创建并存储在我们的缓存中，即 map 对象`m_effectList`：

```cpp
//Lookup audio file in the cached list 
auto iter = m_effectList.find(filePath); 
```

我们在这里做的有趣的方法是创建一个迭代器变量，并将其赋值为`Map.find()`的结果，其中传递的参数是我们要加载的声音文件的位置。这种方法的有趣之处在于，如果在缓存中找不到声音效果，迭代器的值将被设置为地图的末尾对象的索引，从而允许我们进行一个简单的检查，你将看到如下所示：

```cpp
//Failed to find in cache, load 
    if (iter == m_effectList.end()) 
    { 
      Mix_Chunk* chunk = Mix_LoadWAV(filePath.c_str()); 
      //Error Loading file 
      if(chunk == nullptr) 
        throw Exception("Mix_LoadWAV Error: " + 
              std::string(Mix_GetError())); 

      effect.m_chunk = chunk; 
      m_effectList[filePath] = chunk; 
    } 

```

使用迭代器值技巧，我们只需检查`iter`变量的值是否与`Map.end()`函数的返回值匹配；如果是，这意味着音效不在缓存列表中，应该创建。

要加载音效，我们使用`Mix_LoadWAV()`函数，并将文件路径位置作为`c`字符串的参数。我们将返回的对象分配给一个名为块的`Mix_Chunk`指针。

然后我们检查块的值是否为`nullptr`指针，表示加载函数出现错误。如果是`nullptr`指针，我们将抛出一个异常，并提供`Mix_GetError()`函数提供的一些调试信息。如果成功，我们将临时持有者，效果的成员`m_chunk`，赋值为块的值，即我们加载的音效数据。

接下来，我们将这个新加载的效果添加到我们的缓存中，以便将来节省一些工作。

或者，如果我们对`iter`值的检查返回 false，这意味着我们尝试加载的音效在缓存中：

```cpp
else //Found in cache 
    { 
      effect.m_chunk = iter->second; 
    } 

    return effect; 
  } 
```

现在迭代器的真正美丽被揭示了。查找结果，也就是`auto iter = m_effectList.find(filePath);`这一行的结果，当它找到音效时，将指向列表中的音效。所以我们所要做的就是将持有者变量效果成员值`m_chunk`分配给`iter`的第二个值，即音效的数据值。`LoadSoundEffect()`函数中的最后一件事是将效果变量返回给调用方法。这完成了过程，我们的音效现在可以使用了。

在`LoadSoundEffect()`函数之后，是`LoadMusic()`函数：

```cpp
Music BookEngine::AudioManager::LoadMusic(const std::string & filePath) 
  { 
    Music music; 

    //Lookup audio file in the cached list 
    auto iter = m_musicList.find(filePath); 

    //Failed to find in cache, load 
    if (iter == m_musicList.end()) 
    { 
      Mix_Music* chunk = Mix_LoadMUS(filePath.c_str()); 
      //Error Loading file 
      if (chunk == nullptr) 
           throw Exception("Mix_LoadMUS Error: " +
            std::string(Mix_GetError())); 

      music.m_music = chunk; 
      m_musicList[filePath] = chunk; 
    } 
    else //Found in cache 
    { 
      music.m_music = iter->second; 
    } 

    return music; 
  } 
```

我不会详细介绍这个函数，因为您可以看到它非常像`LoadSoundEffect()`函数，但它不是包装`Mix_LoadWAV()`函数，而是包装了`SDL_mixer`库的`Mix_LoadMUS()`。

`AudioManager.cpp`文件中的最后两个函数实现不属于`AudioManager`类本身，而是`SoundEffect`和`Music`辅助类的`Play`函数的实现：

```cpp
 void SoundEffect::Play(int numOfLoops) 
  { 
    if(Mix_PlayChannel(-1, m_chunk, numOfLoops) == -1) 
      if (Mix_PlayChannel(0, m_chunk, numOfLoops) == -1) 
          throw Exception("Mix_PlayChannel Error: " + 
                std::string(Mix_GetError())); 
  } 

  void Music::Play(int numOfLoops) 
  { 
    if (Mix_PlayMusic(m_music, numOfLoops) == -1) 
      throw Exception("Mix_PlayMusic Error: " + 
                 std::string(Mix_GetError())); 
  }   
} 
```

我不会逐行步进每个函数，而是想简单指出这些函数如何在 SDL_mixer 的`Mix_PlayChannel`和`Mix_PlayMusic`函数周围创建包装器。这实质上是`AudioManager`类的目的，它只是一个抽象加载文件和直接创建对象的包装器。这帮助我们创建一个可扩展的框架，管道，而不必担心底层机制。这意味着在任何时候，理论上，我们可以用另一个或甚至多个库替换底层库，而不会影响调用管理器类函数的代码。

为了完成这个示例，让我们看看如何在演示项目中使用这个`AudioManager`。您可以在代码存储库的`Chapter04`文件夹中找到这个演示，标记为`SoundExample`。音乐的来源归功于 Bensound（[`www.bensound.com`](http://www.bensound.com/)）。

从`GameplayScreen.h`文件开始：

```cpp
private: 
  void CheckInput(); 
  BookEngine::AudioManager m_AudioManager; 
  BookEngine::Music m_bgMusic; 
}; 
```

我们在私有声明中添加了两个新对象，一个是名为`m_AudioManager`的`AudioManager`，另一个是名为`m_bgMusic`的`Music`对象。

在`GameplayScreen.cpp`文件中：

```cpp
void GameplayScreen::OnEntry() 
{ 
  m_AudioManager.Init(); 
  m_bgMusic = m_audioManager.LoadMusic("Audio/bensound-epic.mp3"); 
  m_bgMusic.Play(); 
} 
```

要初始化、加载和播放我们的音乐文件，我们需要在`GameplayScreen`类的`OnEntry()`中添加三行。

+   第一行`m_AudioManager.Init()`设置了`AudioManager`并像之前看到的那样初始化了所有组件。

+   接下来加载音乐文件，这里是`bensound-epic.mp3`文件，并将其分配给`m_bgMusic`变量。

+   最后一行`m_bgMusic.Play()`开始播放音乐曲目。通过不传入循环音乐曲目的次数，默认为`-1`，这意味着它将继续循环直到程序停止。

这处理了音乐曲目的播放，但当游戏结束时，我们需要添加一些更多的函数调用来清理`AudioManager`，并在切换屏幕时停止音乐。

为了在离开这个屏幕时停止音乐播放，我们在`GameplayScreen`类的`OnExit`函数中添加以下内容：

```cpp
m_bgMusic.Stop(); 
```

为了清理`AudioManager`并阻止任何潜在的内存泄漏，我们在`GameplayScreen`类的`Destroy`函数中调用以下内容：

```cpp
  m_AudioManager.Destroy(); 
```

这将进而处理我们在前一节中所加载的任何音频资产的销毁和清理。

现在所有这些都已经就位，如果你运行`SoundExample`演示，你将听到一些史诗般的冒险音乐开始播放，并且如果你足够耐心，它将不断循环。现在我们在游戏中有了一些声音，让我们再进一步，看看如何将一些视觉资产导入到我们的项目中。

# 处理纹理

如果你对这个术语不熟悉，纹理基本上可以被认为是一种图像。这些纹理可以应用到一个简单的几何正方形，两个三角形，以制作一幅图像。这种类型的图像通常被称为`Sprite`。我们在本节末尾的演示中使用了`Sprite`类。还需要注意的是，纹理可以应用到更复杂的几何图形中，并且在 3D 建模中用于给物体上色。随着我们在书中后面继续进行演示，纹理将扮演更重要的角色。

# 资源管理器

让我们从高级别的类`ResourceManager`开始。这个管理类将负责在缓存中维护资源对象，并提供一个简单的、抽象的接口来获取资源：

```cpp
#pragma once 
#include "TextureCache.h"
#include <string> 
namespace BookEngine 
{ 
class ResourceManager 
  { 
  public: 
    static GLTexture GetTexture(std::string pathToTextureFile); 
  private: 
    static TextureCache m_textureCache; 
  }; 
} 
```

声明文件`ResourceManager.h`是一个简单的类，包括一个公共函数`GetTexture`，和一个私有成员`TextureCache`。`GetTexure`将是我们向其他类公开的函数。它将负责返回纹理对象。`TextureCache`就像我们在`AudioManager`中使用的缓存，它将保存加载的纹理以供以后使用。让我们继续实现，这样我们就可以看到这是如何设置的：

```cpp
#include "ResourceManager.h"
namespace BookEngine 
{ 
  TextureCache ResourceManager::m_textureCache; 

  GLTexture ResourceManager::GetTexture(std::string texturePath) 
  { 
    return m_textureCache.GetTexture(texturePath); 
  } 
} 
```

`ResourceManager`的实现实际上只是对底层结构的抽象调用。当我们调用`ResourceManager`类的`GetTexture`函数时，我们期望得到一个`GLTexture`类型的返回。作为这个函数的调用者，我不需要担心`TextureCache`的内部工作方式或对象是如何解析的。我所需要做的就是指定我希望加载的纹理的路径，然后资产管道就会完成剩下的工作。这应该是资产管道系统的最终目标，无论采用何种方法，接口都应该足够抽象，以允许开发人员和设计师在项目中导入和使用资产，而不需要底层系统的实现成为阻碍。

接下来我们将看一下这个例子纹理系统，它是`ResourceManager`类接口简单性的核心。

# 纹理和纹理缓存

之前我们看到了`ResourceManager`类结构中引入的两个新对象，`GLTexture`和`TextureCache`。在接下来的章节中，我们将更详细地看一下这两个类，以便了解这些类如何与其他系统连接，构建一个强大的资产管理系统，最终回到`ResourceManager`的简单接口。

首先我们将看一下`GLTexture`类。这个类完全由一个描述我们纹理属性的`struct`组成。以下是`GLTexture`类的完整代码：

```cpp
#pragma once 
#include <GL/glew.h> 
namespace BookEngine 
{ 
  struct GLTexture 
  { 
    GLuint id; 
    int width; 
    int height; 
  }; 
} 
```

如前所述，`GLTexture`类实际上只是一个名为`GLTexture`的`struct`的包装器。这个`struct`保存了一些简单的值。一个`GLuint id`，用于标识纹理和两个整数值，`width`和`height`，当然保存了纹理/图像的高度和宽度。这个`struct`可以很容易地包含在`TextureClass`中，我选择以这种方式实现它，一是为了使它更容易阅读，二是为了允许一些未来发展的灵活性。再次，我们希望确保我们的资产管道允许适应不同的需求和包含新的资产类型。

接下来我们有`TextureCache`类，就像我们对音频资产所做的那样，为图像文件创建一个缓存是一个好主意。这将再次通过将它们保存在一个映射中并根据需要返回它们来为我们提供更快的访问所需的图像文件。我们只需要在缓存中不存在时创建一个新的纹理。在构建任何与资产相关的系统时，我倾向于使用这种带有缓存机制的实现方式。

虽然这些示例提供了一个基本的实现，但它们是创建更健壮的系统的绝佳起点，可以集成内存管理和其他组件。以下是`TextureCache`类的声明，它应该从前面的音频示例中看起来非常熟悉：

```cpp
#pragma once 
#include <map> 
#include "GLTexture.h"

namespace BookEngine 
{ 
  class TextureCache 
  { 
  public: 
    TextureCache(); 
    ~TextureCache(); 

    GLTexture GetTexture(std::string texturePath);  
  private: 
    std::map<std::string, GLTexture> m_textureMap; 

  }; 
} 
```

继续实现`TextureCache`类，在`TextureCache.cpp`文件中，让我们看一下`GetTexture()`：

```cpp
GLTexture TextureCache::GetTexture(std::string texturePath) { 

    //lookup the texture and see if it''''s in the map 
    auto mit = m_textureMap.find(texturePath); 

    //check if its not in the map 
    if (mit == m_textureMap.end()) 
    { 
      //Load the texture 
      GLTexture newTexture = ImageLoader::LoadPNG(texturePath); 

      //Insert it into the map 
      m_textureMap.insert(std::make_pair(texturePath, newTexture)); 

      //std::cout << "Loaded Texture!\n"; 
      return newTexture; 
    } 
    //std::cout << "Used Cached Texture!\n"; 
    return mit->second; 
  }
```

这个实现看起来与我们之前看到的`AudioManager`示例非常相似。这里需要注意的主要一行是调用`ImageLoader`类加载图像文件的那一行，`GLTexture newTexture = ImageLoader::LoadPNG(texturePath);`。这个调用是类的重要部分，正如你所看到的，我们再次抽象了底层系统，只是从我们的`GetTexture`类中提供了一个`GLTexture`作为返回类型。让我们跳到下一节，看一下`ImageLoader`类的实现。

# ImageLoader 类

现在我们已经有了结构来将纹理对象传递回给调用资源管理器，我们需要实现一个实际加载图像文件的类。`ImageLoader`就是这个类。它将处理加载、处理和创建纹理。这个简单的例子将加载一个**便携式网络图形**（**PNG**）格式的图像。

由于我们在这里专注于资产管道的结构，我将坚持课程的核心部分。我将假设您对 OpenGL 的缓冲区和纹理创建有一些了解。如果您对 OpenGL 不熟悉，我强烈推荐 OpenGL 圣经系列作为一个很好的参考。在未来的章节中，当我们研究一些高级渲染和动画技术时，我们将会看到一些这些特性。

在这个例子中，`ImageLoader.h`文件只有一个`LoadPNG`函数的声明。这个函数接受一个参数，即图像文件的路径，并将返回一个`GLTexture`。以下是完整的`ImageLoader`：

```cpp
#pragma once 
#include "GLTexture.h" 
#include <string> 
namespace BookEngine 
{ 
  class ImageLoader 
  { 
  public: 
    static GLTexture LoadPNG(std::string filePath);
    static GLTexture LoadDDS(const char * imagepath);
  }; 
} 
```

继续实现，在`ImageLoader.cpp`文件中，让我们看一下`LoadPNG`函数：

```cpp
... 
  GLTexture ImageLoader::LoadPNG(std::string filePath) { 
unsigned long width, height;     
GLTexture texture = {}; 
std::vector<unsigned char> in; 
  std::vector<unsigned char> out; 
```

我们要做的第一件事是创建一些临时变量来保存我们的工作数据。一个无符号的`长`用于`高度`和`宽度`，一个`GLTexture`对象，然后我们将其所有字段初始化为`0`。然后我们有两个存储无符号字符的向量容器。`in`向量将容纳从 PNG 中读取的原始编码数据。`out`向量将保存已转换的解码数据。

```cpp
  ... 
  //Read in the image file contents into a buffer 
    if (IOManager::ReadFileToBuffer(filePath, in) == false) {
      throw Exception("Failed to load PNG file to buffer!");
    }

    //Decode the .png format into an array of pixels
    int errorCode = DecodePNG(out, width, height, &(in[0]), in.size());
    if (errorCode != 0) {
      throw Exception("decodePNG failed with error: " + std::to_string(errorCode));
    }
  ... 
```

接下来我们有两个函数调用。首先我们调用一个使用`IOManager`类的`ReadFileToBuffer`函数来读取图像文件的原始数据的函数。我们传入`pathToFile`和`in`向量；函数将用原始编码数据填充向量。第二个调用是`DecodePNG`函数；这是我之前提到的单一函数库的调用。这个库将处理原始数据的读取、解码，并用解码后的数据填充输出向量容器。函数有四个参数：

+   第一个是用来保存解码数据的向量，我们的例子中是`out`向量

+   第二个是`width`和`height`变量，`DecodePNG`函数将用图像的值填充它们

+   第三个是指一个容器，它保存着编码数据，在我们的例子中，是`in`向量

+   最后一个参数是缓冲区的大小，也就是向量`in`的大小

这两个调用是这个类的主要部分，它们完成了我们资产管道的图像加载组件的系统。我们现在不会深入到原始数据的读取和解码中。在下一节中，我们将看到一个类似的技术来加载 3D 模型，我们将看到如何详细地读取和解码数据。

函数的其余部分将处理在 OpenGL 中上传和处理图像，我不会在这部分函数上花时间。随着我们继续前进，我们将看到更多 OpenGL 框架的调用，并且在那时我会更深入地讨论。这个例子是专门为 OpenGL 构建的，但它很容易被更通用的代码或特定于其他图形库的代码所替代。

除了`IOManger`和`DecodePNG`类，这就完成了资产管道的图像处理。希望你能看到，有一个像我们所见的这样的结构，可以在底层提供很大的灵活性，同时提供一个简单的接口，几乎不需要了解底层系统。

现在我们通过一个简单的一行调用返回了一个纹理，`ResourceManger::GetTexture(std::string pathToTextureFile)`，让我们把这个例子完整地展示一下，看看我们如何插入这个系统来创建一个`Sprite`（2D 图像）从加载的纹理中：

```cpp
void Sprite::Init(float x, float y, float width, float height, std::string texturePath) { 
        //Set up our private vars 
        m_x = x; 
        m_y = y; 
        m_width = width; 
        m_height = height; 

        m_texture = ResourceManager::GetTexture(texturePath); 
```

在纹理示例项目中，进入`Sprite`类，如果我们关注`Init()`，我们会看到我们的简单接口允许我们调用`ResourceManager`类的`GetTexture`来返回处理过的图像。就是这样，非常简单！当然，这不仅限于精灵，我们可以使用这个函数来加载其他用途的纹理，比如建模和 GUI 用途。我们还可以扩展这个系统，加载不仅仅是 PNG 的文件，事实上，我会挑战你花一些时间为更多的文件格式构建这个系统，比如 DDS、BMP、JPG 和其他格式。`ResourceManager`本身有很大的改进和增长空间。这个基本结构很容易重复用于其他资产，比如声音、3D 模型、字体和其他一切。在下一节中，我们将深入一点，看看加载 3D 模型或网格时的情况。

要看整个系统的运行情况，运行纹理示例项目，你将看到一个由 NASA 的善良人士提供的非常漂亮的太阳图像。

以下是在 Windows 上的输出：

>![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/3a736c0d-67d0-48d3-af09-1d555fcdf520.png)

以下是在 macOS 上的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/aa594644-04dd-475e-8dbf-230a26edc3bf.png)

# 导入模型-网格

模型或网格是三维空间中物体的表示。这些模型可以是玩家角色，也可以是小型景物，比如桌子或椅子。加载和操作这些对象是游戏引擎和底层系统的重要部分。在本节中，我们将看看加载 3D 网格的过程。我们将介绍一种描述三维对象的简单文件格式。我们将学习如何加载这种文件格式并将其解析为可供图形处理器使用的可读格式。最后，我们将介绍 OpenGL 用于渲染对象的步骤。让我们立即开始并从`Mesh`类开始：

```cpp
namespace BookEngine 
{ 
  class Mesh 
  { 
  public: 
    Mesh(); 
    ~Mesh(); 
    void Init(); 
    void Draw(); 
  private: 
    GLuint m_vao; 
    GLuint m_vertexbuffer; 
    GLuint m_uvbuffer; 
    GLTexture m_texture;   

    std::vector<glm::vec3> m_vertices; 
    std::vector<glm::vec2> m_uvs; 
    std::vector<glm::vec3> m_normals; 
    // Won''''t be used at the moment. 
  }; 
} 
```

我们的`Mesh`类声明文件`Mesh.h`非常简单。我们有`normal`构造函数和析构函数。然后我们有另外两个作为`public`公开的函数。`Init()`函数将初始化所有`Mesh`组件，`Draw`函数将实际处理并将信息传递给渲染器。在`private`声明中，我们有一堆变量来保存网格的数据。首先是`GLuint m_vao`变量。这个变量将保存 OpenGL 顶点数组对象的句柄，我现在不会详细介绍，可以参考 OpenGL 文档进行快速了解。

接下来的两个`GLuint`变量，`m_vertexbuffer`和`m_uvbuffer`是用来保存`vertex`和`uv`信息数据的缓冲区。在接下来的实现中会更多介绍。在缓冲区之后，我们有一个`GLTexture`变量`m_texture`。你会记得这个对象类型之前提到过；这将保存网格的纹理。最后三个变量是`glm vec3`的向量。这些向量保存了`Mesh`的顶点的笛卡尔坐标，纹理`uvs`和`normal`。在当前的例子中，我们不会使用 normal 值。

这让我们对`Mesh`类需要什么有了很好的理解；现在我们可以继续实现。我们将逐步学习这个类，遇到其他类时会转到其他类。让我们从`Mesh.cpp`文件开始：

```cpp
namespace BookEngine 
{ 
  Mesh::Mesh() 
  { 
    m_vertexbuffer = 0; 
    m_uvbuffer = 0; 
    m_vao == 0; 
  }
```

`Mesh.cpp`文件以构造函数的实现开始。`Mesh`构造函数将两个缓冲区和顶点数组对象的值设置为零。我们这样做是为了以后进行简单的检查，看它们是否已经被初始化或删除，接下来我们将看到：

```cpp
OBJModel::~OBJModel() 
  { 
    if (m_vertexbuffer != 0) 
      glDeleteBuffers(1, &m_vertexbuffer); 
    if (m_uvbuffer != 0)  
      glDeleteBuffers(1, &m_uvbuffer); 
if (m_vao != 0) 
      glDeleteVertexArrays(1, &m_vao); 
  } 
```

`Mesh`类的析构函数处理了`Buffer`和`Vertex`数组的删除。我们进行简单的检查，看它们是否不等于零，这意味着它们已经被创建，如果它们不是，则删除它们：

```cpp
void OBJModel::Init() 
  {   
    bool res = LoadOBJ("Meshes/Dwarf_2_Low.obj", m_vertices, m_uvs, m_normals); 
    m_texture = ResourceManager::GetTexture("Textures/dwarf_2_1K_color.png"); 
```

接下来是`Init()`函数，我们从加载我们的资源开始。在这里，我们使用熟悉的帮助函数`ResourceManager`类的`GetTexture`函数来获取模型所需的纹理。我们还加载`Mesh`，在这种情况下是一个名为`Dwarf_2_Low.obj`的 OBJ 格式模型，由 andromeda vfx 提供在[TurboSquid.com](https://www.turbosquid.com/)上。这是通过使用`LoadOBJ`函数实现的。让我们暂时离开`Mesh`类，看看这个函数是如何实现的。

在`MeshLoader.h`文件中，我们看到了`LoadOBJ`函数的声明：

```cpp
bool LoadOBJ( 
    const char * path, 
    std::vector<glm::vec3> & out_vertices, 
    std::vector<glm::vec2> & out_uvs, 
    std::vector<glm::vec3> & out_normals 
  ); 
```

`LoadOBJ`函数有四个参数，OBJ 文件的文件路径和三个将填充 OBJ 文件中数据的向量。该函数还具有布尔类型的返回值，这是为了简单的错误检查能力。

在继续查看这个函数是如何组合的，以及它将如何解析数据来填充我们创建的向量之前，重要的是要了解我们正在使用的文件的结构。幸运的是，OBJ 文件是一种开放的文件格式，实际上可以在任何文本编辑器中以纯文本形式阅读。您也可以使用 OBJ 格式手工创建非常简单的模型。举个例子，让我们看一下在文本编辑器中查看的`cube.obj`文件。顺便说一句，您可以在 Visual Studio 中查看 OBJ 格式的 3D 渲染模型；它甚至有基本的编辑工具：

```cpp
# Simple 3D Cube Model 
mtllib cube.mtl 
v 1.000000 -1.000000 -1.000000 
v 1.000000 -1.000000 1.000000 
v -1.000000 -1.000000 1.000000 
v -1.000000 -1.000000 -1.000000 
v 1.000000 1.000000 -1.000000 
v 0.999999 1.000000 1.000001 
v -1.000000 1.000000 1.000000 
v -1.000000 1.000000 -1.000000 
vt 0.748573 0.750412 
vt 0.749279 0.501284 
vt 0.999110 0.501077 
vt 0.999455 0.750380 
vt 0.250471 0.500702 
vt 0.249682 0.749677 
vt 0.001085 0.750380 
vt 0.001517 0.499994 
vt 0.499422 0.500239 
vt 0.500149 0.750166 
vt 0.748355 0.998230 
vt 0.500193 0.998728 
vt 0.498993 0.250415 
vt 0.748953 0.250920 
vn 0.000000 0.000000 -1.000000 
vn -1.000000 -0.000000 -0.000000 
vn -0.000000 -0.000000 1.000000 
vn -0.000001 0.000000 1.000000 
vn 1.000000 -0.000000 0.000000 
vn 1.000000 0.000000 0.000001 
vn 0.000000 1.000000 -0.000000 
vn -0.000000 -1.000000 0.000000 
usemtl Material_ray.png 
s off 
f 5/1/1 1/2/1 4/3/1 
f 5/1/1 4/3/1 8/4/1 
f 3/5/2 7/6/2 8/7/2 
f 3/5/2 8/7/2 4/8/2 
f 2/9/3 6/10/3 3/5/3 
f 6/10/4 7/6/4 3/5/4 
f 1/2/5 5/1/5 2/9/5 
f 5/1/6 6/10/6 2/9/6 
f 5/1/7 8/11/7 6/10/7 
f 8/11/7 7/12/7 6/10/7 
f 1/2/8 2/9/8 3/13/8 
f 1/2/8 3/13/8 4/14/8 
```

正如您所看到的，这些文件中包含了大量的数据。请记住，这只是一个简单的立方体模型的描述。看一下矮人 OBJ 文件，以更深入地了解其中包含的数据。对我们来说重要的部分是`v`、`vt`、`vn`和`f`行。`v`行描述了`Mesh`的几何顶点，即模型在局部空间中的`x`、`y`、`z`值（相对于模型本身的原点的坐标）。`vt`行描述了模型的纹理顶点，这次值是标准化的 x 和 y 坐标，标准化意味着它们是`0`和`1`之间的值。`vn`行是顶点法线的描述，我们在当前示例中不会使用这些，但这些值给出了垂直于顶点的标准化向量单位。在计算光照和阴影等内容时，这些是非常有用的值。以下图示了一个十二面体形状网格的顶点法线：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/ad51a2a6-61ac-40c0-a653-2051ae5fa0e2.png)

最后一组行，`f`行，描述了网格的面。这些是构成网格的单个面，三角形的三个向量值组。这些再次是局部空间的 x、y 和 z 坐标。

在我们的示例引擎中渲染此文件将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/86bfbce9-6b72-4de1-a863-f627e9343062.png)

好了，这就是 OBJ 文件格式的概况，现在让我们继续并看看我们将如何解析这些数据并将其存储在缓冲区中供我们的渲染器使用。在`MeshLoader.cpp`文件中，我们找到了`LoadOBJ()`函数的实现：

```cpp
... 
bool LoadOBJ( 
    std::string path, 
    std::vector<glm::vec3> & out_vertices, 
    std::vector<glm::vec2> & out_uvs, 
    std::vector<glm::vec3> & out_normals 
    )  
{ 
    WriteLog(LogType::RUN, "Loading OBJ file " + path + " ..."); 
    std::vector<unsigned int> vertexIndices, uvIndices, normalIndices; 
    std::vector<glm::vec3> temp_vertices; 
    std::vector<glm::vec2> temp_uvs; 
    std::vector<glm::vec3> temp_normals; 
```

为了开始`LoadOBJ`函数，创建了一些占位变量。变量声明的第一行是三个整数向量。这些将保存`vertices`、`uvs`和`normals`的索引。在索引之后，我们有另外三个向量。两个`vec3`向量用于`vertices`和`normal`，一个`vec2`向量用于`uvs`。这些向量将保存每个临时值，允许我们执行一些计算：

```cpp
    try  
{ 
std::ifstream in(path, std::ios::in); 
```

接下来我们开始一个`try`块，它将包含函数的核心逻辑。我们这样做是为了在这个函数的最后内部抛出一些异常，如果出现任何问题就在内部捕获它们。`try`块中的第一行，`std::ifstream in(path, std::ios::in);`尝试加载我们传入位置的文件。`ifstream`，正如您可能已经注意到的，是标准库的一部分，用于定义一个流对象，可以用来从文件中读取字符数据。在现代 I/O 系统中经常看到`ifstream`的使用，它是 C++中常见的`fopen`的替代品，后者实际上是 C 的：

```cpp
if (!in) {
throw Exception("Error opening OBJ file: " + path); }
```

然后我们可以测试是否有任何加载文件错误，使用简单的 if 语句`if(!in)`，这与直接检查状态标志相同，例如`in.bad() == true;`或`in.fail() == true`。如果我们遇到错误，我们会抛出一个带有调试消息的异常。我们稍后在函数中处理这个异常：

```cpp
std::string line; 
while (std::getline(in, line)) 
  { 
```

接下来，我们需要创建一个循环，这样我们就可以遍历文件并根据需要解析数据。我们使用`while()`循环，使用`std::getline(in, line)`函数作为参数。`std::getline`返回一行字符，直到它达到一个换行符。`parameters std::getline()`接受的是包含字符的流，我们的情况下是`in`，以及一个将保存函数输出的`std::string`对象。

通过将这个作为`while`循环的条件参数，我们将继续逐行遍历输入文件，直到达到文件的末尾。在条件变为假的时间内，我们将停止循环。这是一个非常方便的逐步遍历文件以解析的方法：

```cpp
  if (line.substr(0, 2) == "v ") { 
    std::istringstream v(line.substr(2)); 
    glm::vec3 vert; 
    double x, y, z; 
    v >> x; v >> y; v >> z; 
    vert = glm::vec3(x, y, z); 
    temp_vertices.push_back(vert); 
  } 
```

在我们的`while`循环内，我们首先要尝试解析的是 OBJ 文件中的顶点数据。如果你还记得我们之前的解释，顶点数据包含在一个单独的行中，用`v`表示。然后，为了解析我们的顶点数据，我们应该首先测试一下这行是否是一个顶点（`v`）行。`std::string()`对象有一个方便的方法，允许你从字符串中选择一定数量的字符。这个方法就是`substr()`，`substr()`方法可以接受两个参数，字符在字符串中的起始位置和结束位置。这样就创建了一个子字符串对象，然后我们可以对其进行测试。

在这个例子中，我们使用`substr()`方法来取字符串`line`的前两个字符，然后测试它们是否与字符串`"v "`（注意空格）匹配。如果这个条件是`true`，那就意味着我们有一个顶点行，然后可以继续将其解析成我们系统中有用的形式。

这段代码相当容易理解，但让我们来强调一些重要的部分。首先是`std::istringstream`对象`v`。`stringstream`是一个特殊的对象，它提供了一个字符串缓冲区，方便地操作字符串，就像操作 I/O 对象（`std::cout`）一样。这意味着你可以使用`>>`和`<<`操作符来处理它，也可以使用`str()`方法来像处理`std::string`一样处理它。我们使用我们的字符串流对象来存储一组新的字符。这些新字符是通过对`line.substr(2)`的方法调用提供的。这一次，通过只传递一个参数`2`给`substr`方法，我们告诉它返回从第二个字符开始的行的其余部分。这样做的效果是返回顶点行的值`x`、`y`和`z`，而不包括`v`标记。一旦我们有了这组新的字符，我们就可以逐个遍历每个字符，并将其分配给它匹配的双精度变量。正如你所看到的，这就是我们使用字符串流对象的独特性来将字符流到它的变量的地方，即`v >> x;``v >> y; v >> x;`行。在`if`语句的末尾，我们将这些`x`、`y`、`z`双精度数转换为`vec3`，最后将新创建的`vec3`推送到临时`vertices`向量的末尾：

```cpp
else if (line.substr(0, 2) == "vt")  
{ 
std::istringstream v(line.substr(3)); 
          glm::vec2 uv; 
          double U, V; 
          v >> U;v >> V; 
          uv = glm::vec2(U, V); 
          uv.y = -uv.y; 
          temp_uvs.push_back(uv); 
        } 
```

对于纹理，我们做了很多相同的事情。除了检查`"vt"`之外，主要的区别是我们只寻找两个值，或者`vec2`向量。这里的另一个注意事项是我们反转了`v`坐标，因为我们使用的是纹理格式，它们是反转的。如果你想使用 TGA 或 BMP 格式的加载器，可以删除这部分：

```cpp
        else if (line.substr(0, 2) == "vn") 
 { 

          std::istringstream v(line.substr(3)); 
          glm::vec3 normal; 
          double x, y, z; 
          v >> x;v >> y;v >> z; 
          normal = glm::vec3(x, y, z); 
          temp_normals.push_back(normal); 
        } 
```

对于法线，我们做的和顶点一样，但是寻找的是`vn`行：

```cpp

        else if (line.substr(0, 2) == "f ") 
        { 
          unsigned int vertexIndex[3], uvIndex[3], normalIndex[3]; 
          const char* cstring = line.c_str(); 
          int matches = sscanf_s(cstring, "f %d/%d/%d %d/%d/%d %d/%d/%d\n", &vertexIndex[0], &uvIndex[0], &normalIndex[0], &vertexIndex[1], &uvIndex[1], &normalIndex[1], &vertexIndex[2], &uvIndex[2], &normalIndex[2]); 
```

对于面，一个三角形的集合，我们做一些不同的事情。首先，我们检查是否有一个`"f "`行。如果有，我们设置一些数组来保存`vertex`，`uv`和`normal`的索引。然后我们将我们的`std::string`，line，转换为一个字符数组，即 C 字符串，使用`const char* cstring = line.c_str();`这一行。然后我们使用另一个 C 函数，`sscanf_s`来解析实际的字符串，并将每个字符分离到特定的索引数组元素中。一旦这个语句完成，`sscanf_s()`函数将返回一个元素集的整数值，我们将其赋给变量 matches：

```cpp
if (matches != 9) 
    throw Exception("Unable to parse format"); 
```

然后我们使用`matches`变量来检查它是否等于`9`，这意味着我们有九个元素，这是我们可以处理的格式。如果 matches 的值不是`9`，那意味着我们有一个我们没有设置好处理的格式，所以我们抛出一个带有简单调试消息的异常：

```cpp
          vertexIndices.push_back(vertexIndex[0]); 
          vertexIndices.push_back(vertexIndex[1]); 
          vertexIndices.push_back(vertexIndex[2]); 
          uvIndices.push_back(uvIndex[0]); 
          uvIndices.push_back(uvIndex[1]); 
          uvIndices.push_back(uvIndex[2]); 
          normalIndices.push_back(normalIndex[0]); 
          normalIndices.push_back(normalIndex[1]); 
          normalIndices.push_back(normalIndex[2]); 
        } 
      }
```

在`"f "`或面行的 if 语句中，我们做的最后一件事是将所有分离的元素推入相应的索引向量中。我们使用这些值来构建实际的网格数据：

```cpp
      for (unsigned int i = 0; i < vertexIndices.size(); i++)  
{ 
        // Get the indices of its attributes 
        unsigned int vertexIndex = vertexIndices[i]; 
        unsigned int uvIndex = uvIndices[i]; 
        unsigned int normalIndex = normalIndices[i]; 
```

为了创建我们的最终网格数据以提供输出向量，我们创建另一个循环来遍历模型数据，这次使用一个 for 循环和顶点数量作为条件。然后我们创建三个变量来保存每个`vertex`，`uv`和`normal`的当前索引。每次我们通过这个循环，我们将这个索引设置为`i`的值，这个值在每一步中递增：

```cpp
        glm::vec3 vertex = temp_vertices[vertexIndex - 1]; 
        glm::vec2 uv = temp_uvs[uvIndex - 1]; 
        glm::vec3 normal = temp_normals[normalIndex - 1]; 
```

然后，由于这些索引值，我们可以获得每个`vertex`，`uv`和`normal`的属性。我们将这些设置为`vec2`或`vec3`，这是我们输出向量所需要的：

```cpp
        out_vertices.push_back(vertex); 
        out_uvs.push_back(uv); 
        out_normals.push_back(normal); 
      } 
    } 
```

最后，最后一步是将这些新值推入它们特定的输出向量中：

```cpp
    catch (Exception e) 
    { 
      WriteLog(LogType::ERROR, e.reason); 
      return false; 
    } 
    return true; 
  } 
  ...
```

最后，我们有一个`catch`块来匹配顶部的`try`块。这个 catch 非常简单，我们从传入的`Exception`对象中取出 reason 成员对象，并用它来将调试消息打印到错误日志文件中。我们还从`LoadOBJ()`函数中返回 false，以让调用对象知道发生了错误。如果没有什么可捕捉的，我们简单地返回 true，以让调用对象知道一切都按预期工作。现在我们准备使用这个函数来加载我们的 OBJ 文件，并为渲染系统生成有用的数据。

现在，回到`Mesh.cpp`文件，我们将继续使用这个加载的数据来使用示例引擎绘制模型。我不会在每个函数上花太多时间，这再次是特定于 OpenGL API，但可以以更通用的方式编写，或者使用其他图形库，比如 DirectX：

```cpp
    if (m_vao == 0)  
      glGenVertexArrays(1, &m_vao); 
    glBindVertexArray(m_vao); 
```

在这里，我们检查顶点数组对象是否已经生成；如果没有，我们使用我们的`m_vao`作为引用对象来创建一个。接下来我们绑定 VAO，这将允许我们在这个类中的所有后续 OpenGL 调用中使用它：

```cpp
    if (m_vertexbuffer == 0) 
glGenBuffers(1, &m_vertexbuffer); 
    if (m_uvbuffer == 0)  
      glGenBuffers(1, &m_uvbuffer); 
```

接下来我们检查我们的顶点缓冲是否已经创建；如果没有，我们使用`m_vertexbuffer`变量作为引用对象来创建一个。我们对`uvbuffer`也是同样的操作：

```cpp
    glBindBuffer(GL_ARRAY_BUFFER, m_vertexbuffer); 
    glBufferData(GL_ARRAY_BUFFER, m_vertices.size() * sizeof(glm::vec3), &m_vertices[0], GL_STATIC_DRAW); 
    glBindBuffer(GL_ARRAY_BUFFER, m_uvbuffer); 
    glBufferData(GL_ARRAY_BUFFER, m_uvs.size() * sizeof(glm::vec2), &m_uvs[0], GL_STATIC_DRAW); 
  }
```

在我们的`Meshes Init()`函数中，我们做的最后一件事是绑定`vertex`和`uv`缓冲区，然后使用 OpenGL 的`glBindBuffer()`和`glBufferData()`函数将数据上传到图形卡上。查看 OpenGL 文档以获取有关这些函数的更详细信息：

```cpp
  void Mesh::Draw() 
  {   
    glActiveTexture(GL_TEXTURE0); 
    glBindTexture(GL_TEXTURE_2D, m_texture.id); 
```

对于`Mesh`类的`Draw()`函数，我们首先在 OpenGL API 框架中设置纹理。我们使用函数调用`glActiveTexture()`来激活纹理，使用`glBindTexture()`来实际绑定内存中的纹理数据：

```cpp
    glBindBuffer(GL_ARRAY_BUFFER, m_vertexbuffer); 
    glVertexAttribPointer( 0,  3,  GL_FLOAT,  GL_FALSE,  0, (void*)0); 
    glBindBuffer(GL_ARRAY_BUFFER, m_uvbuffer); 
    glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 0, (void*)0); 
```

接下来我们绑定缓冲区并设置顶点数据和纹理坐标数据的属性。同样，我不会在这里专注于细节，代码中有注释来解释每个参数。关于这些函数的更多信息，我建议在线查看 OpenGL 文档。

```cpp
    glDrawArrays(GL_TRIANGLES, 0, m_vertices.size()); 
```

当所有数据都绑定，并且所有属性都设置好之后，我们可以调用函数来实际绘制`Mesh`对象。在这种情况下，我们使用`glDrawArrays()`函数，传入`GL_TRIANGLES`作为绘制的方法。这意味着我们要使用三角形来渲染顶点数据。尝试将这个值更改为`GL_POINTS`来玩玩。

```cpp
    glDisableVertexAttribArray(0); 
    glDisableVertexAttribArray(1); 
    glBindBuffer(GL_ARRAY_BUFFER, 0); 
  } 
}
```

在我们的绘制调用结束时，我们还有最后一步要完成，清理工作。在每次 OpenGL 绘制调用之后，需要禁用已设置的使用过的属性，并解绑已使用的缓冲区。`glDisableVertexAttribArray()`和`glBindBuffer()`函数用于这些任务。

在`GameplayScreen.cpp`文件中，我们添加了初始化模型的调用：

```cpp
 ... 
//Init Model 
  m_model.Init("Meshes/Dwarf_2_Low.obj", "Textures/dwarf_2_1K_color.png"); 
  ... 
```

然后我们可以通过简单地在`GameplayScreen`的`Draw()`函数中添加对模型的`Draw()`函数的调用来开始绘制它：

```cpp
  ... 
//Draw Model 
  m_model.Draw(); 
... 
```

就是这样！如果你运行`ModelExample`，你会在屏幕上看到矮人模型的输出。我还为游戏添加了一个简单的 3D 摄像头，这样你就可以在模型周围移动。在游戏空间中，使用`W`、`A`、`S`和`D`来移动摄像头。使用鼠标来四处看。

以下是在 Windows 上的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/3b10abf5-6f28-4d57-9bda-a5ada9fa57a4.png)

以下是在 macOS 上的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/f83fd587-2824-447e-867f-26f6bff4ddee.png)

# 总结

在本章中，我们涵盖了开发中非常重要的一个部分，即处理资产。我们看了一下导入、处理和管理内容（如声音、图像和 3D 对象）的过程。有了这个基础系统，我们可以继续完善游戏开发所需的其余系统。

在下一章中，我们将着眼于开发核心的游戏玩法系统，包括状态系统、物理系统、摄像头和 GUI/HUD 系统。


# 第五章：构建游戏系统

我们已经到了我们的旅程中的一个节点，我们能够开始将我们将用来驱动我们的游戏和工具的各种系统逐步拼凑在一起。这些系统是引擎的一部分，它们为我们现在能够导入游戏中的所有惊人资产提供互动的动力：

+   理解状态

+   设计摄像机系统

+   使用物理

# 理解状态

我们以许多不同的方式使用状态。它们可以用于控制游戏流程，处理角色行为和反应的不同方式，甚至用于简单的菜单导航。不用说，状态是强大且可管理的代码基础的重要要求。

有许多不同类型的状态机；我们将在本节中重点关注**有限状态机（FSM）**模式。你们中的敏锐读者可能已经注意到，我们已经在实现的屏幕系统的功能中看到了 FSM 模式。事实上，我们将在这里创建的东西与为该系统创建的东西非常相似，只是有一些关键的区别，这将使其成为一个更通用和灵活的状态机。

我们可以在游戏中实现简单状态机的几种方式。一种方式是简单地使用 switch case 来控制状态，并使用`enum`结构来表示状态类型。一个例子如下：

```cpp
enum PlayerState 
{ 
    Idle, 
      Walking 
} 
... 
PlayerState currentState = PlayerState::Idle; //A holder variable for the state currently in 
... 
// A simple function to change states 
void ChangeState(PlayState nextState) 
{ 
    currentState = nextState; 
} 
void Update(float deltaTime) 
{ 
    ... 
    switch(currentState) 
{ 
    case PlayerState::Idle: 
        ... //Do idle stuff 
        //Change to next state 
ChangeState(PlayerState::Walking); 
break; 
        case PlayerState::Walking: 
            ... //Do walking stuff 
            //Change to next state 
            ChangeState(PlayerState::Idle); 
break; 
    } 
    ... 
} 
```

像这样使用 switch/case 对于许多情况来说是有效的，但它确实有一些强大的缺点。如果我们决定添加一些新的状态怎么办？如果我们决定添加分支和更多的`if`条件呢？

我们开始时使用的简单 switch/case 突然变得非常庞大，无疑难以控制。每当我们想要进行更改或添加一些功能时，我们就会增加复杂性，并引入更多的错误机会。通过采用稍微不同的方法并使用类来表示我们的状态，我们可以帮助减轻一些这些问题，并提供更多的灵活性。通过继承和多态性的使用，我们可以构建一个结构，允许我们将状态链接在一起，并提供在许多情况下重用它们的灵活性。

让我们逐步了解如何在我们的演示示例中实现这一点，从我们将来将继承的基类`IState`开始：

```cpp
... 
namespace BookEngine 
{ 
    class IState { 
    public: 
        IState() {} 
        virtual ~IState(){} 
        // Called when a state enters and exits  
        virtual void OnEntry() = 0; 
        virtual void OnExit() = 0; 

        // Called in the main game loop 
        virtual void Update(float deltaTime) = 0; 
    }; 
} 
```

正如你所看到的，这只是一个非常简单的类，它有一个构造函数，一个虚拟析构函数，以及三个完全虚拟的函数，每个继承的状态都必须重写。`OnEntry`将在状态首次进入时调用，每次状态更改时只执行一次。`OnExit`和`OnEntry`一样，每次状态更改时只执行一次，并在状态即将退出时调用。最后一个函数是`Update`函数；这将在每个游戏循环中调用，并包含大部分状态的逻辑。虽然这看起来非常简单，但它给了我们一个很好的起点来构建更复杂的状态。现在让我们在我们的示例中实现这个基本的`IState`类，并看看我们如何将其用于状态机的一个常见需求：创建游戏状态。

首先，我们将创建一个名为`GameState`的新类，它将继承自`IState`。这将是我们的游戏所需的所有状态的新基类。`GameState.h`文件包括以下内容：

```cpp
#pragma once 
#include <BookEngine\IState.h> 
class GameState : BookEngine::IState 
{ 
public: 
    GameState(); 
    ~GameState(); 
    //Our overrides 
    virtual void OnEntry() = 0; 
    virtual void OnExit() = 0; 
    virtual void Update(float deltaTime) = 0; 
    //Added specialty function 
    virtual void Draw() = 0; 
}; 
```

`GameState`类非常类似于它继承的`IState`类，除了一个关键的区别。在这个类中，我们添加了一个新的虚拟方法`Draw()`，所有继承自`GameState`的类现在都将实现它。每次我们使用`IState`并创建一个新的专门的基类，比如玩家状态、菜单状态等，我们可以添加这些新函数来根据状态机的要求进行定制。这就是我们如何使用继承和多态性来创建更复杂的状态和状态机。

继续我们的示例，现在让我们创建一个新的`GameState`。我们首先创建一个名为`GameWaiting`的新类，它继承自`GameState`。为了更容易跟踪，我将所有新的`GameState`继承类分组到一个名为`GameStates.h`和`GameStates.cpp`的文件集中。`GamStates.h`文件将如下所示：

```cpp
#pragma once 
#include "GameState.h" 

class GameWaiting: GameState 
{ 
    virtual void OnEntry() override; 
    virtual void OnExit() override; 
    virtual void Update(float deltaTime) override; 
    virtual void Draw() override; 
}; 

class GameRunning: GameState 
{ 
    virtual void OnEntry() override; 
    virtual void OnExit() override; 
    virtual void Update(float deltaTime) override; 
    virtual void Draw() override; 
}; 

class GameOver : GameState 
{ 
    virtual void OnEntry() override; 
    virtual void OnExit() override; 
    virtual void Update(float deltaTime) override; 
    virtual void Draw() override; 
}; 
```

这里没有什么新东西；我们只是声明了每个`GameState`类的函数。现在，在我们的`GameStates.cpp`文件中，我们可以按照前面的代码实现每个单独状态的函数。

```cpp
#include "GameStates.h" 
    void GameWaiting::OnEntry() 
{ 
...  
//Called when entering the GameWaiting state's OnEntry function 
... 
} 

void GameWaiting::OnExit() 
{ 
...  
//Called when entering the GameWaiting state's OnEntry function 
... 
} 

void GameWaiting::Update(float deltaTime) 
{ 
...  
//Called when entering the GameWaiting state's OnEntry function 
... 

} 

void GameWaiting::Draw() 
{ 
...  
//Called when entering the GameWaiting state's OnEntry function 
... 

} 
...  
//Other GameState implementations  
... 
```

出于页面空间的考虑，我只显示了`GameWaiting`的实现，但其他状态也是一样的。每个状态都将有其自己独特的这些函数实现，这使您能够控制代码流程并根据需要实现更多状态，而不会创建一个难以遵循的代码路径迷宫。

现在我们已经定义了我们的状态，我们可以在游戏中实现它们。当然，我们可以以许多不同的方式进行。我们可以遵循与屏幕系统相同的模式，并实现一个`GameState`列表类，其定义可能如下所示：

```cpp
    class GameState; 

    class GameStateList { 
    public: 
        GameStateList (IGame* game); 
        ~ GameStateList (); 

        GameState* GoToNext(); 
        GameState * GoToPrevious(); 

        void SetCurrentState(int nextState); 
        void AddState(GameState * newState); 

        void Destroy(); 

        GameState* GetCurrent(); 

    protected: 
        IGame* m_game = nullptr; 
        std::vector< GameState*> m_states; 
        int m_currentStateIndex = -1; 
    }; 
} 
```

或者我们可以简单地使用我们创建的`GameState`类与一个简单的`enum`和一个 switch case。状态模式的使用允许这种灵活性。在示例中，我选择了与屏幕系统相同的设计；您可以在源代码存储库中看到`GameStateExample`项目的完整实现。值得浏览源代码，因为我们将在整本书中继续使用这些状态设计。尝试修改示例；添加一个创建与其他状态不同的屏幕打印的新状态。您甚至可以尝试在状态内部嵌套状态，以创建更强大的代码分支能力。

# 与相机一起工作

到目前为止，我们已经讨论了系统结构的很多内容，现在我们已经能够继续设计与我们的游戏和 3D 环境交互的方式。这将我们带到一个重要的话题：虚拟相机系统的设计。相机是为我们提供 3D 世界的视觉表示的东西。这是我们如何沉浸自己，并为我们选择的交互提供反馈。在本节中，我们将讨论计算机图形学中虚拟相机的概念。

在我们开始编写相机代码之前，了解它的工作原理非常重要。让我们从能够在 3D 世界中导航的想法开始。为了做到这一点，我们需要使用所谓的变换管道。变换管道可以被认为是相对于相机视点的位置和方向来转换所有对象和点所采取的步骤。以下是一个详细说明变换管道流程的简单图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/3452a528-196c-4721-87af-496f5aca1405.png)

从管道的第一步开始，局部空间，当一个网格被创建时，它有一个局部原点 0 x，0 y，0 z。这个局部原点通常位于对象的中心，或者在一些玩家角色的情况下，位于脚的中心。构成该网格的所有点都是基于该局部原点的。当谈论一个尚未转换的网格时，我们称之为处于局部空间中。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/39326e41-9c69-40b2-af8d-ee369ac280a0.png)

上图显示了在模型编辑器中的侏儒网格。这就是我们所谓的局部空间。

接下来，我们想将一个网格带入我们的环境，即世界空间。为了做到这一点，我们必须将我们的网格点乘以所谓的模型矩阵。然后将网格放置在世界空间中，这将使所有网格点相对于单个世界原点。最容易将世界空间想象为描述构成游戏环境的所有对象的布局。一旦网格被放置在世界空间中，我们就可以开始做一些事情，比如比较距离和角度。这一步的一个很好的例子是在世界/关卡编辑器中放置游戏对象；这是在与其他对象和单个世界原点（0,0,0）相关的模型网格的描述。我们将在下一章更详细地讨论编辑器。

接下来，为了在这个世界空间中导航，我们必须重新排列点，使它们相对于摄像机的位置和方向。为了实现这一点，我们进行了一些简单的操作。首先是将对象平移到原点。首先，我们会将摄像机从其当前的世界坐标移动。

在下面的示例图中，*x*轴上有**20**，*y*轴上有**2**，*z*轴上有**-15**，相对于世界原点或**0,0,0**。然后我们可以通过减去摄像机的位置来映射对象，即用于平移摄像机对象的值，这种情况下为**-20**，**-2**，**15**。因此，如果我们的游戏对象在*x*轴上开始为**10.5**，在*y*轴上为**1**，在*z*轴上为**-20**，则新的平移坐标将是**-9.5**，**-1**，**-5**。最后一个操作是将摄像机旋转到所需的方向；在我们当前的情况下，这意味着指向-*z*轴。对于下面的示例，这意味着将对象点旋转**-90**度，使示例游戏对象的新位置为**5**，**-1**，**-9.5**。这些操作组合成所谓的视图矩阵：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/a47e37f1-60e7-46d4-93c7-82d8ce00cbb5.png)

在我们继续之前，我想简要介绍一些重要的细节，当涉及到处理矩阵时，特别是处理矩阵乘法和操作顺序。在使用 OpenGL 时，所有矩阵都是以列主布局定义的。相反的是行主布局，在其他图形库中可以找到，比如微软的 DirectX。以下是列主视图矩阵的布局，其中 U 是指向上的单位向量，F 是我们指向前方的向量，R 是右向量，P 是摄像机的位置：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/21b8ec10-e037-4bb2-b309-2fb5b85d7d33.png)

构建一个矩阵时，其中包含平移和旋转的组合，比如前面的视图矩阵，通常不能简单地将旋转和平移值放入单个矩阵中。为了创建一个正确的视图矩阵，我们需要使用矩阵乘法将两个或多个矩阵组合成一个最终的矩阵。记住我们使用的是列主记法，因此操作的顺序是从右到左。这很重要，因为使用方向（R）和平移（T）矩阵，如果我们说 V = T x R，这将产生一个不希望的效果，因为这首先会将点围绕世界原点旋转，然后将它们移动到与摄像机位置对齐。我们想要的是 V = R x T，其中点首先与摄像机对齐，然后应用旋转。在行主布局中，当然是相反的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/1a829f1e-437e-43fb-b03c-e69e8fdbf898.png)

好消息是，我们不一定需要手动处理视图矩阵的创建。OpenGL 的旧版本和大多数现代数学库，包括 GLM，都有一个`lookAt()`函数的实现。大多数函数需要相机位置、目标或观察位置以及上方向作为参数，并返回一个完全创建好的视图矩阵。我们将很快看到如何使用 GLM 的`lookAt()`函数的实现，但如果你想看到刚才描述的想法的完整代码实现，请查看项目源代码库中包含的 GLM 的源代码。

继续通过变换管线，下一步是从眼空间转换为齐次裁剪空间。这个阶段将构建一个投影矩阵。投影矩阵负责一些事情。

首先是定义近裁剪平面和远裁剪平面。这是沿着定义的前向轴（通常为*z*）的可见范围。任何落在近距离前面或者远距离后面的物体都被视为超出范围。在后续步骤中，处于此范围之外的任何几何对象都将被*裁剪*（移除）。

第二步是定义**视野**（**FOV**）。尽管名字是视野，但实际上是一个角度。对于 FOV，我们实际上只指定了垂直范围；大多数现代游戏使用 66 或 67 度。水平范围将由矩阵根据我们提供的宽高比（宽度相对于高度）来计算。举例来说，在 4:3 宽高比的显示器上，67 度的垂直角度将有一个 FOV 为 89.33 度（*67 * 4/3 = 89.33*）。

这两个步骤结合起来创建了一个形状类似于被截去顶部的金字塔的体积。这个创建的体积被称为视锥体。任何落在这个视锥体之外的几何体都被视为不可见。

以下图示了视锥体的外观：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/8f7c74c5-f2d2-4d17-86f8-d91a3f38037e.png)

你可能会注意到在视锥体的末端有更多的可见空间。为了在 2D 屏幕上正确显示这一点，我们需要告诉硬件如何计算透视。这是管线中的下一步。视锥体的较大、远端将被推在一起，形成一个盒子形状。在这个宽端可见的物体也将被挤在一起；这将为我们提供一个透视视图。要理解这一点，想象一下看着一条笔直的铁轨。随着铁轨延伸到远处，它们看起来会变得更小、更接近。

在定义裁剪空间之后，管线中的下一步是使用所谓的透视除法将点归一化为一个具有尺寸为(-1 到 1，-1 到 1，-1 到 1)的盒子形状。这被称为**归一化设备空间**。通过将尺寸归一化为单位大小，我们允许点被乘以以缩放到任何视口尺寸。

变换管线中的最后一个重要步骤是创建将要显示的 3D 的 2D 表示。为了做到这一点，我们将归一化设备空间中的远处物体绘制在靠近摄像机的物体后面（绘制深度）。尺寸从*X*和*Y*的归一化值被缩放为视口的实际像素值。在这一步之后，我们有了一个称为**视口空间**的 2D 空间。

这完成了转换管道阶段。有了这个理论，我们现在可以转向实现并编写一些代码。我们将从创建一个基本的第一人称 3D 摄像机开始，这意味着我们是通过玩家角色的眼睛观察。让我们从摄像机的头文件`Camera3D.h`开始，它可以在源代码库的`Chapter05`项目文件夹中找到。

```cpp
... 
#include <glm/glm.hpp> 
#include <glm/gtc/matrix_transform.hpp> 
..., 
```

我们从必要的包含开始。正如我刚提到的，GLM 包括支持使用矩阵，所以我们包括`glm.hpp`和`matrix_transform.hpp`来获得 GLM 的`lookAt()`函数的访问权限。

```cpp
... 
   public: 
      Camera3D(); 
      ~Camera3D(); 
      void Init(glm::vec3 cameraPosition = glm::vec3(4,10,10), 
              float horizontalAngle = -2.0f,  
              float verticalAngle = 0.0f,  
              float initialFoV = 45.0f); 
      void Update(); 
```

接下来，我们有 Camera3D 类的公共可访问函数。前两个只是标准的构造函数和析构函数。然后是`Init()`函数。我们声明这个函数时提供了一些默认值，这样如果没有传入值，我们仍然有值可以在第一次更新调用中计算我们的矩阵。这将带我们到下一个声明的函数，`Update()`函数。这是游戏引擎每次循环调用以保持摄像机更新的函数。

```cpp
glm::mat4 GetView() { return m_view; };
glm::mat4 GetProjection() { return m_projection; };
glm::vec3 GetForward() { return m_forward; };
glm::vec3 GetRight() { return m_right; };
glm::vec3 GetUp() { return m_up; };
```

在`Update()`函数之后，有一组五个获取函数，用于返回视图和投影矩阵，以及摄像机的前向、向上和向右向量。为了保持实现的整洁，我们可以在头文件中简单地声明和实现这些*getter*函数。

```cpp
void SetHorizontalAngle(float angle) { m_horizontalAngle = angle; };
void SetVerticalAngle(float angle) { m_verticalAngle = angle; };
```

在获取函数集之后，我们有两个设置函数。第一个将设置水平角度，第二个将设置垂直角度。当屏幕大小或纵横比发生变化时，这是很有用的。

```cpp
void MoveCamera(glm::vec3 movementVector) { m_position +=   movementVector; };
```

Camera3D 类中的最后一个公共函数是`MoveCamera()`函数。这个简单的函数接收一个向量 3，然后将该向量累加到`m_position`变量中，这是当前摄像机的位置。

```cpp
...
  private:
    glm::mat4 m_projection;
    glm::mat4 m_view; // Camera matrix
```

对于类的私有声明，我们从两个`glm::mat4`变量开始。`glm::mat4`是 4x4 矩阵的数据类型。我们创建一个用于视图或摄像机矩阵，一个用于投影矩阵。

```cpp
glm::vec3 m_position;
float m_horizontalAngle;
float m_verticalAngle;
float m_initialFoV;
```

接下来，我们有一个单一的三维向量变量来保存摄像机的位置，然后是三个浮点值——一个用于水平角度，一个用于垂直角度，以及一个用于保存视野的变量。

```cpp
glm::vec3 m_right;
glm::vec3 m_up;
glm::vec3 m_forward; 
```

然后我们有另外三个向量 3 变量类型，它们将保存摄像机对象的右、上和前向值。

现在我们已经声明了我们的 3D 摄像机类，下一步是实现头文件中尚未实现的任何函数。我们只需要提供两个函数，`Init()`和`Update()`函数。让我们从`Init()`函数开始，它位于`Camera3D.cpp`文件中。

```cpp
void Camera3D::Init(glm::vec3 cameraPosition, 
     float horizontalAngle, 
     float verticalAngle, 
     float initialFoV)
   {
     m_position = cameraPosition;
     m_horizontalAngle = horizontalAngle;
     m_verticalAngle = verticalAngle;
     m_initialFoV = initialFoV;

     Update();
    }
    ...

```

我们的`Init()`函数很简单；在函数中，我们只是接收提供的值并将它们设置为我们声明的相应变量。一旦我们设置了这些值，我们只需调用`Update()`函数来处理新创建的摄像机对象的计算。

```cpp
...
   void Camera3D::Update()
   {
      m_forward = glm::vec3(
          glm::cos(m_verticalAngle) * glm::sin(m_horizontalAngle),
          glm::sin(m_verticalAngle),
          glm::cos(m_verticalAngle) * glm::cos(m_horizontalAngle)
        );
```

`Update()`函数是类的所有繁重工作都在做的地方。它首先计算摄像机的新前向。这是通过利用 GLM 的余弦和正弦函数的简单公式来完成的。正在发生的是，我们正在从球坐标转换为笛卡尔坐标，以便我们可以在创建我们的视图矩阵中使用该值。

```cpp
  m_right = glm::vec3(
        glm::sin(m_horizontalAngle - 3.14f / 2.0f),
        0,
        glm::cos(m_horizontalAngle - 3.14f / 2.0f)
     );  
```

在计算了新的前向之后，我们然后使用一个简单的公式计算摄像机的新右向量，再次利用 GLM 的正弦和余弦函数。

```cpp
 m_up = glm::cross(m_right, m_forward);
```

现在我们已经计算出了前向和向上的向量，我们可以使用 GLM 的叉积函数来计算摄像机的新向上向量。这三个步骤在摄像机改变位置或旋转之前，以及在创建摄像机的视图矩阵之前发生是很重要的。

```cpp
  float FoV = m_initialFoV;
```

接下来，我们指定视野。目前，我只是将其设置回初始化摄像机对象时指定的初始视野。如果摄像机被放大或缩小，这将是重新计算视野的地方（提示：鼠标滚轮可能在这里很有用）：

```cpp
m_projection = glm::perspective(glm::radians(FoV), 4.0f / 3.0f, 0.1f, 100.0f);
```

一旦我们指定了视野，我们就可以计算摄像机的投影矩阵。幸运的是，GLM 有一个非常方便的函数叫做`glm::perspective()`，它接受弧度制的视野、宽高比、近裁剪距离和远裁剪距离，然后返回一个创建好的投影矩阵。由于这只是一个示例，我指定了一个 4:3 的宽高比（4.0f/3.0f）和一个直接的裁剪空间从 0.1 单位到 100 单位。在生产中，你理想情况下会将这些值移动到可以在运行时更改的变量中：

```cpp
 m_view = glm::lookAt(
            m_position,           
            m_position + m_forward, 
            m_up
         );
      }
```

最后，在`Update()`函数中我们要做的是创建视图矩阵。正如我之前提到的，我们很幸运，GLM 库提供了一个`lookAt()`函数，用于抽象我们在本节前面讨论的所有步骤。这个`lookAt()`函数接受三个参数。第一个是摄像机的位置。第二个是摄像机指向的矢量值，或者*看向*的位置，我们通过简单地将摄像机当前位置和计算出的前向矢量相加来提供。最后一个参数是摄像机当前的上矢量，同样，我们之前计算过。完成后，这个函数将返回新更新的视图矩阵，供我们在图形管线中使用。

这就是一个简单的 3D 摄像机类。继续运行 CameraDemo 项目，看看系统是如何运作的。你可以用 WASD 键移动摄像机，用鼠标改变视角。接下来，我们将转向另一个重要的游戏引擎系统，物理！

# 处理物理

如今，很少有游戏不实现至少一些基本形式的物理。游戏物理的话题相当庞大和复杂，很容易填满几卷书才能算是全面覆盖。正因为如此，整个团队都致力于创建*物理引擎*，并且可能需要数年的开发才能构建生产级系统。因为情况如此，我们不会尝试在这里覆盖所有方面，而是采取更高层次的方法。我们将覆盖一些更常见的物理系统方面，特别是基本的碰撞检测。对于更高级的需求，比如支持重力、摩擦和高级碰撞检测，我们将覆盖第三方物理库的实现。在本节结束时，我们的演示引擎将具有高级的物理支持。

# AABB 中的点

首先，让我们来看看在 3D 中可以执行的较简单的碰撞检查之一，即找出一个点是否在**轴对齐边界框**（**AABB**）内或外。AABB 非常容易创建。你可以基本上将其想象成不可旋转的立方体或盒子。以下图像描述了 AABB 和点之间的碰撞：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/c502b9d4-9123-486a-b50f-59304240a90f.png)

要创建一个边界框，你可以指定一个向量格式的最大点和最小点，或者通过指定一个中心点，然后指定高度、宽度和深度。在这个例子中，我们将使用最小点和最大点的方法创建我们的 AABB：

```cpp
struct BoundingBox
{
 glm::vec3 m_vecMax;
 glm::vec3 m_vecMin;
};  
```

前面的代码是一个简单的 AABB 结构的示例。

现在我们有了一个 AABB，我们可以开发一种方法来检查单个点是否落在 AABB 内。这个检查非常简单；我们只需要检查它的所有值，x、y 和 z，是否大于 AABB 的最小值并且小于 AABB 的最大值。在代码中，这个检查看起来会像下面这样，以最简单的形式：

```cpp
bool PointInAABB(const BoundingBox& box, const glm::vec3 & vecPoint)
 {
   if(vecPoint.x > tBox.m_vecMin.x && vecPoint.x < tBox.m_vecMax.x &&
      vecPoint.y > tBox.m_vecMin.y && vecPoint.y < tBox.m_vecMax.y &&
      vecPoint.z > tBox.m_vecMin.z && vecPoint.z < tBox.m_vecMax.z)
     {
         return true;
     }
    return false;
  }

```

# AABB 到 AABB

现在我们已经看到如何测试一个点是否在某个 AABB 内，接下来我们将看到的非常有用的碰撞检查是 AABB 到 AABB 的检查——一个快速测试，以找出两个 AABB 是否发生碰撞。以下图像描述了这个碰撞检查：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/8e4f7aad-e66f-4e3a-8635-cc8f2162973e.png)

两个 AABB 之间的碰撞检查非常简单和快速。这是大多数需要一种碰撞检测形式的对象的常见选择。

AABB 的不好之处在于它们不能旋转。一旦它们旋转，它们就不再是 AABB，因为它们不再与*x*、*y*和*z*轴对齐。对于旋转的对象，更好的选择是使用球体、胶囊体，甚至是**定向包围盒**（**OBBs**）。

要检查两个 AABB 是否发生碰撞，我们只需要检查第一个 AABB 的最大点是否大于第二个 AABB 的最小点，并且第一个 AABB 的最小点是否小于第二个 AABB 的最大点。以下是这个检查在代码中的简单形式：

```cpp
bool AABBtoAABB(const BoundingBox& box1, const BoundingBox& box2) 
{ 
 if (box1.m_vecMax.x > tBox2.m_vecMin.x &&  
    box1.m_vecMin.x < tBox2.m_vecMax.x && 
    box1.m_vecMax.y > tBox2.m_vecMin.y && 
    box1.m_vecMin.y < tBox2.m_vecMax.y && 
    box1.m_vecMax.z > tBox2.m_vecMin.z && 
    box1.m_vecMin.z < tBox2.m_vecMax.z)  
{  
   return true; 
} 
return false; 
} 
```

当然，盒子的顺序，哪一个是第一个，哪一个是第二个，都无关紧要。

由于这个检查包含很多`&&`比较，如果第一个检查是假的，它将不会继续检查其余的；这就是允许非常快速测试的原因。

# 球到球

我想在这里谈论的最后一个简单的碰撞检查是测试两个球体是否相互碰撞。测试球体之间的碰撞非常简单且易于执行。球体相对于 AABB 等物体的优势在于，不管物体是否旋转，球体都将保持不变。以下是描述两个球体之间碰撞检查的图像：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/ee43bc1c-46b3-4415-8767-a9bd4b83e28d.png)

为了进行检查，我们只需要计算球心之间的距离，并将其与它们的半径之和进行比较。如果这个距离小于它们的半径之和，那么球体重叠。如果相同，那么球体只是接触。以下是这个碰撞测试在代码中的简单形式：

```cpp
... 
struct BoundingSphere 
{ 
glm::vec3    m_vecCenter; 
float          m_radius; 
}; 
... 
bool SphereToSphere(const BoundingSphere & Sphere1, const BoundingSphere & Sphere2) 
{ 

glm::vec3 distance(Sphere2.m_vecCenter - Sphere1.m_vecCenter); 
float distanceSqaured(glm::dot( & distance, & distance) ); 

```

为了得到球心之间的距离，我们需要创建一个连接它们中心点的向量：

```cpp
float radiiSumSquared( Sphere1.m_radius + Sphere2.m_radius ); 
radiiSumSquared *= radiiSumSquared; 
```

然后我们可以计算该向量与半径之和的长度：

有一种更有效的方法。由于向量与自身的点积等于该向量的平方长度，我们可以只计算该向量的平方长度与半径之和的平方。如果我们这样做，就不需要计算向量的长度，这本身就是一个昂贵的操作。

```cpp
if( distanceSqaured <= radiiSumSquared ) 
{ 
    return true; 
} 
return false; 
} 
... 
```

最后，我们可以进行碰撞检查。如果距离的平方小于或等于平方和，那么球体已经碰撞，否则，物体没有碰撞，我们返回 false。

有了这些简单的检查，大多数基本的碰撞检测都可以处理。事实上，正如我们将在下一节中看到的，大多数高级检查都由许多较小的检查组成。然而，总会有一个时刻，你会发现自己需要更高级或优化的物理处理方式；这时你可以求助于第三方库来提供支持。在下一节中，我们将看一下其中一个第三方库的实现。

# 实现 Bullet 物理库。

Bullet 是一个模拟碰撞检测和软体和刚体动力学的物理引擎。它已经被用于许多发布的视频游戏以及电影中的视觉效果。Bullet 物理库是免费的开源软件，受 zlib 许可证的条款约束。

Bullet 提供的一些功能包括：

+   刚体和软体模拟，使用离散和连续碰撞检测

+   碰撞形状：球、盒子、圆柱、锥体、使用 GJK 的凸壳、非凸和三角网格

+   软体支持：布料、绳索和可变形物体

具有约束限制和电机的丰富的刚体和软体约束集。

你可以在以下网址找到源代码链接和更多信息：[`bulletphysics.org`](http://bulletphysics.org)。

让我们看看如何将 Bullet 引入到你自己的游戏项目中。我不打算花时间讲解如何将库链接到我们的演示项目，因为我们已经讲解了几次了。如果你需要复习，请翻回几章看看。我们要做的是将 Bullet 引擎整合到我们的演示引擎中，然后使用 Bullet 引擎的计算来实时定位我们的游戏对象。在这个例子中，我们将创建一个简单的地面平面，然后一个球（球体）下落并与地面碰撞。我们将使用 Bullet 的内置类型来支持这一点，包括重力以给它一个真实的效果。

从地面`GameObject`开始，我们设置了一些需要的物理值的变量。第一个是`btCollisionShape`类型。这是一个 Bullet 类型，允许在创建物理测试的边界对象时定义简单的形状。接下来是`btDefaultMotionState`类型，这也是一个 Bullet 数据类型，描述了物体在运动时的行为方式。我们需要的最后一个变量是`btRigidBody`类型，这是一个 Bullet 数据类型，将保存我们的物理引擎关心的物体的所有物理属性：

```cpp
class GroundObject : BookEngine::GameObject 
{ 
   ... 

   btCollisionShape* groundShape = nullptr; 
   btDefaultMotionState* groundMotionState = nullptr; 
   btRigidBody* groundRigidBody = nullptr; 
```

一旦我们定义了这些变量，我们就可以在`Init()`函数中构建地面对象的物理表示：

```cpp
void GroundObject::Init(const glm::vec3& pos, const glm::vec3& scale) 
{ 
   ... 
   groundShape = new btStaticPlaneShape(btVector3(0, 1, 0), 1); 
   groundMotionState = 
      new btDefaultMotionState(btTransform(btQuaternion(0, 0, 0, 1), btVector3(m_position.x, m_position.y, m_position.z))); 
```

我们首先将我们的`groundShape`变量设置为`btStaticPlanShape`。这是一个指定简单平面对象的 Bullet 对象，非常适合我们的需要和一个简单的地面对象。接下来，我们设置`groundMotionState`。我们通过使用`btDefaultMotionState` Bullet 对象来实现这一点。`btDefaultMotionState`是用于指定物体在运动中的行为方式的类型。创建一个新的`btDefaultMotionState`时，我们需要传入一些关于物体变换的信息，即物体的旋转和位置。为此，我们传入一个`btTransform`对象，其自身参数为四元数格式的旋转（`btQuaternion(0, 0, 0, 1)`）和三维向量格式的位置（`btVector3(m_position.x, m_position.y, m_position.z)`）：

```cpp
btRigidBody::btRigidBodyConstructionInfo 
 groundRigidBodyCI(0, groundMotionState, groundShape, btVector3(0, 0,  0)); 
 groundRigidBody = new btRigidBody(groundRigidBodyCI); 
```

现在，`groundShape`和`groundMotionState`设置好了，我们可以继续创建和设置刚体信息。首先，我们为构造信息定义了一个`btRigidBodyConstuctionInfo`变量，名为`groundRigidBodyCI`。这个对象接受一些参数值，一个标量值来指定质量，物体的运动状态，碰撞形状，以及一个三维向量来指定局部惯性值。惯性是任何物体对其运动状态的任何改变的抵抗力。基本上是物体保持以恒定速度直线运动的倾向。

由于我们的地面对象是静态的，不需要根据物理输入进行任何更改，我们可以跳过`Update()`函数，继续进行我们将用来测试系统的 Ball 对象。

进入`BallObject.h`文件，我们定义了一些我们需要的变量，就像我们为地面对象做的那样。我们创建了一个运动状态，一个标量（整数）值用于质量，碰撞形状，最后是一个刚体：

```cpp
btDefaultMotionState* fallMotionState;
btScalar mass = 1;
btCollisionShape* fallShape;
btRigidBody* fallRigidBody;
...  
```

现在，进入`BallObject.cpp`文件，我们为刚刚定义的变量分配一些值：

```cpp
void BallObject::Init(const glm::vec3& pos, const glm::vec3& scale)
 {
    ...

    fallShape = new btSphereShape(10);
    btVector3 fallInertia(0.0f, 0.0f, 0.0f);  
```

首先，我们设置碰撞形状。在这种情况下，我们将使用类型`btSphereShape`。这是球体的默认形状，并接受一个参数来设置球体的半径。接下来，我们创建一个三维向量来保存球体的惯性。我们将其设置为全零，因为我们希望这个球体根据物体的质量和我们即将设置的重力值自由下落，没有阻力：

```cpp
fallMotionState =
       new btDefaultMotionState(btTransform(btQuaternion(0, 0, 0, 1),     
       btVector3(m_position.x, m_position.y, m_position.z)));
```

接下来，我们设置球的运动状态，就像我们为地面物体做的一样。我们将旋转设置为 0，位置设置为球对象的当前位置：

```cpp
 fallShape->calculateLocalInertia(mass, fallInertia);
    btRigidBody::btRigidBodyConstructionInfo fallRigidBodyCI(mass,  fallMotionState, fallShape, fallInertia);
    fallRigidBody = new btRigidBody(fallRigidBodyCI);
     }

```

然后我们使用方便的`calculateLocalInertia()`函数计算局部惯性值，传入质量和`fallInertia`值。这将设置我们的球对象的下落向量，用于物理引擎的第一个 tick。最后，我们以与之前地面对象完全相同的方式设置刚体对象。

对于球对象，我们确实希望物理引擎的输出会影响球对象。正因为如此，我们需要在球对象的`Update()`函数中进行一些调整：

```cpp
void BallObject::Update(float deltaTime)
 {
    btTransform trans;
    fallRigidBody->getMotionState()->getWorldTransform(trans);
    m_position.x = trans.getOrigin().getX();
    m_position.y = trans.getOrigin().getY();
    m_position.z = trans.getOrigin().getZ();
  }
```

对于球对象的更新循环中的第一步是从刚体获取物理对象的变换。一旦我们有了这个变换对象，我们就可以将球对象的网格（可见对象）设置为物理变换对象的位置。这就是对象本身的全部内容。球和地面对象现在包含了所有所需的物理信息。现在我们可以将物理引擎循环实现到我们的游戏循环中，并让球滚动，不是在开玩笑！

对于将物理引擎实现到我们现有的游戏引擎循环中，我们首先需要设置一些值。进入我们的`Gameplayscreen.h`，我们定义变量来保存这些值：

```cpp
btBroadphaseInterface* broadphase = new btDbvtBroadphase();  
```

首先是`btBroadphaseInterface`类对象的定义，它提供了一个 Bullet 接口来检测 AABB 重叠的对象对。在这种情况下，我们将其设置为`btDbvtBroadphase`，它使用两个动态 AABB 边界体积层次/树来实现`btBroadphase`。当处理许多移动对象时，这往往是最好的广相位；它的对象插入/添加和移除通常比在`btAxisSweep3`和`bt32BitAxisSweep3`中找到的扫描和修剪广相位更快：

```cpp
btDefaultCollisionConfiguration* collisionConfiguration = new     
       btDefaultCollisionConfiguration();
btCollisionDispatcher* dispatcher = new              
       btCollisionDispatcher(collisionConfiguration); btSequentialImpulseConstraintSolver* solver = new    
       btSequentialImpulseConstraintSolver;
```

接下来，我们已经为碰撞配置、碰撞分发器和顺序脉冲约束求解器定义了。我们不会深入讨论每一个，但主要观点是碰撞配置设置了一些 Bullet 内部值，比如碰撞检测堆栈分配器和池内存分配器。碰撞分发器是处理碰撞的定义。它支持处理*凸凸*和*凸凹*碰撞对的算法，时间的影响，最近的点和穿透深度。最后，顺序脉冲约束求解器定义了可以被认为是算法，将决定如何解决物体之间的碰撞。对于那些希望了解的人，这是一种**单指令，多数据**（**SIMD**）实现的投影高斯-塞德尔（迭代 LCP）方法：

```cpp
btDiscreteDynamicsWorld* dynamicsWorld = new       
     btDiscreteDynamicsWorld(dispatcher, broadphase, solver,    
     collisionConfiguration);
```

我们需要定义的最后一个变量是我们的动态世界对象。`btDiscreteDynamicsWorld`提供了离散刚体模拟。这可以被认为是发生物理模拟的环境或*世界*。一旦我们定义了这个，我们就有了开始物理模拟的所有要素。

让我们跳转到`GameplayScreen.cpp`文件，看看我们将用来初始化物理模拟的`OnEntry()`函数：

```cpp
void GameplayScreen::OnEntry() 
{ 
   ... 

   dynamicsWorld->setGravity(btVector3(0, -1, 0)); 
   dynamicsWorld->addRigidBody(m_ground.groundRigidBody); 
   dynamicsWorld->addRigidBody(m_ball.fallRigidBody); 
... 
} 
```

我们设置的第一件事是重力向量。在我们的简单示例中，我们将其设置为*y*轴上的`-1`。接下来，我们将两个创建的刚体添加到模拟环境中，一个用于地面，一个用于球。这处理了我们物理引擎的初始化；现在我们需要在每个引擎 tick 上更新它：

```cpp
void GameplayScreen::Update(float deltaTime) 
{ 
   CheckInput(deltaTime); 
   dynamicsWorld->stepSimulation(1 / 60.f, 10); 
   m_ball.Update(deltaTime); 
```

在`GameplayScreen::Update()`函数中，我们首先检查输入，然后调用物理引擎的更新，最后调用游戏对象本身的更新。重要的是要注意这个顺序。我们首先要接受用户的输入，但我们要确保在对象之前已经更新了物理引擎。原因是物理计算应该对对象产生一些影响，我们不希望出现绘图循环领先于物理循环的情况，因为这肯定会导致一些不需要的效果。您还会注意到物理更新函数`stepSimulation`接受两个参数。第一个是要按时间步长模拟的时间量。这通常是自上次调用它以来的时间。在这种情况下，我们将其设置为 1/60 秒，或 60 FPS。第二个参数是 Bullet 允许每次调用它执行的最大步数。如果您将一个非常大的值作为第一个参数传递，比如，是固定内部时间步长或游戏时钟大小的五倍，那么您必须增加`maxSubSteps`的数量来补偿这一点；否则，您的模拟将*丢失*时间，这将再次导致一些不需要的物理计算输出。

就是这样！我们现在有一个物理引擎在运行其模拟，并影响我们在屏幕上绘制的世界中的对象。您可以通过在`Chapter05` GitHub 存储库中运行`PhysicsDemo`示例项目来看到这一点。输出将类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/587278a9-af53-427b-b6bc-759b806a024a.png)

# 总结

在本章中，我们涵盖了很多内容，并在开发专业级项目所需的核心游戏系统方面取得了良好的进展。我们现在拥有自己的自定义游戏状态系统，可以被游戏引擎中的许多其他组件采用。我们在构建对摄像机的工作原理的理解的同时，开发了自己的自定义摄像机系统。最后，我们看了一下如何通过将 Bullet 物理引擎添加到我们的示例引擎中，可以向我们的项目添加完整的第三方游戏系统。


# 第六章：创建图形用户界面

在游戏中，用户交互是设计中非常重要的一部分。能够为用户提供视觉信息和视觉选择的能力是**图形用户界面**（**GUI**）的作用所在。与本书中讨论的许多其他系统一样，已经有现成的库可供使用。在开源游戏开发世界中最常见的一个是**Crazy Eddies GUI**（**CEGUI**）。虽然 CEGUI 是一个非常强大的 GUI 系统实现，但随着这种强大性而来的是复杂性，老实说，大多数时候你真的只需要一个文本标签、一个简单的按钮，也许还有一个复选框和图标支持。有了这些简单的构建模块，你就可以创建很多东西。

在本章中，我们将构建基本组件并创建一个简单的 GUI 系统。需要注意的是，从头开始创建一个完整的、可生产的 GUI 系统是一项艰巨的任务，不是一个单独的章节可以完成的。因此，我们将专注于核心概念，并构建一个可以在以后扩展和扩展的系统。我们的 GUI 将不使用任何 API 特定内容，并将继续构建前几章创建的结构。本章涉及的主题如下：

+   坐标系统和定位

+   添加控制逻辑

+   渲染 GUI

本章的完整代码示例可以在代码存储库的`Chapter06`文件夹中找到。为了简洁起见，我将省略一些非必要的代码行，并可能更频繁地跳转文件和类。

# 坐标系统和定位

每个 GUI 系统中最重要的部分之一是对象/元素在屏幕上的位置。在大多数情况下，图形 API 使用称为屏幕空间的坐标，通常表示为绝对范围[-1,1]。虽然这对于渲染是很好的，但在尝试开发我们的 GUI 系统时可能会引起一些问题。例如，让我们以使用绝对系统的想法为例。在这个系统中，我们将明确地将 GUI 中的每个元素设置为真实的像素坐标。这可能很容易实现，但只有在游戏的分辨率保持不变的情况下才能工作。如果我们在任何时候改变分辨率，元素将保持锁定在其像素坐标上，并且不会按比例缩放以匹配新的分辨率。

另一个选择是创建一个相对系统，其中每个 GUI 元素的位置都是相对于其他元素或屏幕位置描述的。这种方法比绝对系统好得多，但仍然存在一些缩放问题。例如，如果我们在屏幕的左上角放置了一个带有小偏移的元素，如果游戏的分辨率在任何时候发生了变化，我们使用的间距也会发生变化。

我们要构建的是 CEGUI 所采用的一种类似方法，这是前面提到的两种解决方案的结合。与此同时，我们还将添加现代 GUI 中使用的另一个常见约定：将组合的元素包含在*面板*中。我们希望将 GUI 元素分组在面板中有几个很好的理由。首先，如果我们想移动一堆元素，比如一个带有健康、弹药和物品指示器的状态栏，如果我们将它们分组在一个面板中，我们只需要移动面板，所有元素都会正确地跟随移动。这就引出了第二个原因：通过在面板中将元素分组在一起，我们可以定义元素相对于面板位置的位置，而不是将元素位置设置为像素坐标或相对于屏幕位置。

以下是描述此设计布局的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/00836859-220f-4875-a4cd-a99dcc87cd00.png)

如您所见，使用了相对和绝对定位的组合，但这次相对起始点不是整个屏幕的原点**[0,0]**，而是我们面板的原点**[0,0]**。虽然面板的原点在屏幕上已经有一些坐标，但我们不使用它们来设置元素的位置。

理论上，我们现在在面板内有可扩展的元素，但我们仍然需要一种方法来*锁定*或*固定*面板的位置，而不受屏幕分辨率的影响。这就是 GUI 锚点系统的概念发挥作用的地方。如果您以前使用过 GUI，很可能已经看到过锚点的作用。在我们的例子中，为了节省时间，我们将稍微简化这个概念。在我们的系统中，每个面板都将能够将其原点相对于五个锚点之一设置：左上、右上、左下、右下和中心。

以下图表演示了这个概念：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/6b2ce10a-aa70-43a8-bdfe-a91cdf9d5897.png)

好的，那么我们如何在代码中实现这些概念并设计它们呢？让我们从一个所有其他元素都将继承的`IGUIElement`类开始。看一下`IGUIElement`类：

```cpp
class IGUIElement
{
public:
virtual void Update() = 0;
glm::vec2 GetPosition() { return m_position; };
protected:
glm::vec2 m_position;
};
}
```

首先，我们的元素并不复杂。每个元素都将有一个`Update()`函数，以及一个 getter 函数来返回元素的位置。我们将在本章后面扩展这个类。

我们可以实现系统的下一部分是面板的概念。让我们从`IGUIPanel.h`的头文件开始看一下：

```cpp
...
static enum class GUIAnchorPos {
TopRight,
TopLeft,
BottomRight,
BottomLeft,
Center
};
...
```

文件以声明一个名为`GUIAnchorPos`的`enum class`开始；这个`enum`将给元素们访问计算出的锚点的权限。我们将这个`enum`类作为`IGUIPanel`类内部的一个`enum`，而不是一个`IGUIPanel`实例的需要，这样可以让元素们在不需要`IGUIPanel`实例的情况下访问锚点。后面，我们将看到一个将这些枚举值连接到已计算出的屏幕位置的函数。

```cpp
...
IGUIPanel(glm::vec4 panelBounds = glm::vec4(0,0,200,480),
glm::vec2 panelAnchor = glm::vec2(0,0),
glm::vec2 offset = glm::vec2(0,0));
...
```

文件中感兴趣的下一部分是构造函数。在这里，我们要求传入一个 vector 4 来定义要创建的面板的边界。接下来，我们要求一个 vector two 来定义面板锚点的原点位置，以及一个 vector two 来提供面板位置的偏移或*填充*。您还会注意到，我们还为每个参数提供了一些默认值。我们这样做有几个原因，但最重要的原因是我们希望能够默认创建 GUI 元素并将它们附加到面板上。通过提供默认值，如果我们创建了一个 GUI 元素，而没有现有的面板可以附加它，我们可以在创建时不需要传入值来创建一个面板。我们将在本章后面重新讨论这个问题。让我们继续实现：

```cpp
IGUIPanel::IGUIPanel(glm::vec4 panelBounds, glm::vec2 panelAnchor, glm::vec2 offset) : m_bounds(panelBounds), m_offset(offset)
{
  m_Pos = panelAnchor + m_offset;
  m_panelWidth = m_bounds.z;
  m_panelHeight = m_bounds.w;
}
```

对于`IGUIPanel`构造函数的实现，我们首先要计算的是面板在屏幕上的位置。我们通过将面板的锚点与传入的偏移相加来实现这一点，并将其存储在受保护的成员变量`m_Pos`中。接下来，我们计算面板的宽度和高度；我们使用传入的边界值来实现这一点。我们分别将它们存储在名为`m_panelWidth`和`m_panelHeight`的受保护成员变量中。

现在我们已经放置了面板构造函数，我们可以继续设置面板如何保存它们的元素。为了实现这一点，我们简单地创建了一个名为`m_GUIElementList`的`IGUIElements`指针的向量。然后我们可以开始创建一些公共方法来访问和操作面板的元素列表：

```cpp
...
  void IGUIPanel::AddGUIElement(IGUIElement & GUIElement)
  {
     m_GUIElement.List.push_back(&GUIElement);
  }
...
```

首先，在`IGUIPanel.cpp`文件中，我们创建一个`AddGUIElement()`函数来向面板添加新元素。这个函数实现了对面板元素列表的`push_back()`方法的调用，将给定的`GUIElement`引用推入其中：

```cpp
virtual std::vector<IGUIElements*>& GetGUIElementList() 
{ 
   return m_ GetGUIElementList; 
};
```

跳转到`IGUIPanel.h`文件，我们实现了一个 getter 函数`GetGUIElementList()`，以提供对私有元素列表的公共访问：

```cpp
void IGUIPanel::Update()
{
  for (auto const& element : m_ m_GUIElement.List)
  {
     element ->Update();
  }
}
```

切换回`IGUIPanel.cpp`文件，我们可以查看面板类的`Update()`函数的实现。这个更新将遍历面板的元素列表，然后调用列表中每个元素的`Update()`函数。这将允许面板控制其元素的更新，并为实现诸如在面板隐藏时暂停元素更新等概念提供结构：

```cpp
IGUIPanel::~IGUIPanel()
{
  std::for_each(m_GUIElementList.begin(),
  m_ GUIElementList.end(),
  std::default_delete<IGUIElement>());
}
```

最后，我们需要记住在调用析构函数时清理属于面板的所有元素。为此，我们将使用`standard`库的`for_each()`方法。我们主要使用这个方法是因为这是一个例子，而且我想向你介绍它。`for_each()`方法接受三个参数。前两个应用于范围，第三个是要执行的函数。在我们的例子中，我们将在我们遍历的每个元素上调用`default_delete()`，再次使用这个方法是为了向你介绍这个函数。`default_delete()`函数实际上是一个函数对象类，其类似函数的调用接受一个模板化的对象类型并删除它。这可以与简单使用 delete 进行删除操作的非专门化版本或用于数组的专门化版本`delete[]`进行比较。这个类专门设计用于与`unique_ptr`一起使用，并提供了一种在没有开销的情况下删除`unique_ptr`对象的方法。

好了，现在我们已经放置了`IGUIPanel`类，我们可以继续构建我们 GUI 系统所需的更复杂的元素。在这个例子中，我们将添加一个带有标签支持的基本按钮：

```cpp
...
class IGUIButton : public IGUIElement
{
 public:
 IGUIButton(glm::vec4& bounds,
 glm::vec2& position,
 GLTexture* texture,
 std::string label,
 SpriteFont* font,
 glm::vec2& fontScale = glm::vec2(1.0f),
 IGUIPanel* panel = NULL);
 ~IGUIButton();
 virtual void Update() override;
...
```

在`IGUIButton.h`文件中，我们可以看到按钮继承自我们基本的`IGUIElement`。这当然意味着我们可以访问父类的所有函数和受保护的成员，包括`m_position`和`GetPosition()`函数，因此我们不在这里重新定义它们。当我们查看`IGUIButton.h`时，我们还可以看一下构造函数，在那里我们定义了创建按钮时需要传入的内容。在我们的示例按钮中，我们正在寻找按钮的边界（大小），位置，绘制按钮时要使用的纹理，按钮的标签（要显示的文本），用于标签的字体，字体的比例（我们默认为`1.0f`），最后是要将按钮添加到的面板，默认为`NULL`，除非另有说明。随着我们继续本章，我们将更深入地研究这些参数。

在构造函数的实现方面，在`IGUIButton.cpp`中，在`IGUIButton::IGUIButton(glm::vec4 & bounds, glm::vec2 & position, std::string label, GLTexture * texture, SpriteFont* font, glm::vec2& fontScale, IGUIPanel* panel)`之前：

```cpp

m_texture(*texture),
m_buttonLabel(label),
m_spriteFont(font),
m_fontScale(fontScale),
m_panel(panel)
{
   m_bounds = bounds;
   if (m_panel != NULL)
   {
   m_position = *m_panel->GetPosition() + position;
```

在大部分情况下，我们只是将内部成员变量设置为传入的值，但值得注意的是我们如何处理面板的值。在构造函数体中，我们进行了一个检查，看看`m_panel`中存储的值是否为空。如果这个检查为真，我们可以继续设置按钮元素相对于面板位置的位置。我们首先调用面板的`GetPosition()`函数，将返回的值添加到我们传入的位置值中，并将该计算保存在`m_position`成员变量中。这将部分地通过将按钮的位置设置为面板的关系原点来给我们想要的东西，但由于默认面板元素的原点是左下角，结果是按钮被放置在面板的底部。这不一定是期望的行为。为了纠正这一点，我们需要根据面板的顶部计算按钮的新*y*轴值，当然还有面板中已经存在的元素：

```cpp
//Move to just below the last element in the list
if (!m_panel->GetGUIElementList().empty())
{
  IGUIElement* lastElement = m_panel-> GetGUIElementList().back();
  m_position.y = lastElement ->GetPosition().y -
  lastElement ->GetBounds().w -
  10.0f; // Used as default padding (should be dynamic)
}
else
{
   //Move to top of panel
   m_position.y += m_panel->GetBounds()->w - m_bounds.w;
   }
  }
}
```

首先，我们要检查我们要添加按钮的面板是否已经有任何现有元素。我们通过检查面板的向量和`GetGUIElementList().empty()`函数来实现这一点。如果面板的元素列表不为空，我们需要获取面板列表中最后一个元素的位置。我们通过创建一个临时元素`lastElement`并使用`GetGUIElementList().back()`将其赋值为面板列表中的最后一个元素来实现这一点。有了存储的元素，我们可以用它来计算按钮的*y*轴值。我们通过从存储的元素的*y*轴值减去存储的元素的高度(`GetBounds().w`)和一个默认的填充值来实现这一点，在这个例子中我们将填充值设置为`10.0f`。在完整的 GUI 实现中，您可能希望使这个填充值动态化。最后，如果面板是空的，并且这是第一个元素，我们通过计算面板的高度(`GetBounds()->w`)减去新按钮的高度来设置按钮的*y*轴。这将把按钮元素放在面板的顶部。

现在我们有了一个带有元素类和实现的按钮元素的面板系统。我们需要做的最后一件事是构建一个高级类来将系统粘合在一起。我们将创建一个`IGUI`类，它将容纳面板，为其他游戏系统提供对 GUI 方法的访问，并且，正如我们将在接下来的部分中看到的，提供输入、更新和绘制机制。让我们跳转到`IGUI.cpp`文件中的构造函数实现：

```cpp
IGUI::IGUI(Window& window) : m_window(window)
{
...
m_BL = new glm::vec2( 
                      0,
                      0
                      );
m_BR = new glm::vec2( 
                      m_window.GetScreenWidth(),
                      0
                      );
m_TL = new glm::vec2( 
                      0,
                      m_window.GetScreenHeight()
                      );
m_TR = new glm::vec2( 
                      m_window.GetScreenWidth(),                     
                      m_window.GetScreenHeight()
                     );
m_C = new glm::vec2( 
                     m_window.GetScreenWidth() * 0.5f,                 
                     m_window.GetScreenHeight() * 0.5f
                     );
 ...
```

在`IGUI`类的构造函数中，我们将定义我们将用于`IGUI`实例中保存的所有面板的锚点。我们将把这些值存储在私有成员变量中：`m_BL`表示屏幕左下角，`m_BR`表示屏幕右下角，`m_TL`表示屏幕左上角，`m_TR`表示屏幕右上角，`m_C`表示屏幕中心。我们使用设置`m_window`窗口对象来返回用于计算锚点的屏幕的宽度和高度。我们将看到这些点如何用于后面的课程中为面板提供锚点。

接下来，让我们看一下我们将用来将元素和面板添加到`IGUI`实例中的函数。

```cpp
void IGUI::AddGUIElement(IGUIElement& GUIElement)
{
   if (!m_GUIPanelsList.empty())
  {
   m_GUIPanelsList[0]->AddGUIObject(GUIElement);
   }
   else
   {
   IGUIPanel* panel = new IGUIPanel();
   m_GUIPanelsList.push_back(panel);
   m_GUIPanelsList[0]->AddGUIObject(GUIElement);
   }
}
```

从`AddGUIElement`函数开始，这个函数，正如它的名字所暗示的那样，将一个 GUI 元素添加到 GUI 中。默认情况下，元素将被添加到 GUI 的面板列表中找到的第一个面板中，这些面板存储在`m_GUIPanelsList`向量中。如果面板列表为空，我们将创建一个新的面板，将其添加到列表中，然后最终将元素添加到该面板中：

```cpp
void IGUI::AddGUIPanel(IGUIPanel& GUIPanel)
{
  m_GUIPanelsList.push_back(&GUIPanel);
}
```

`AddGUIPanel()`函数非常简单。我们使用`push_back()`向量方法将传入的`IGUIPanel`对象添加到 GUI 的面板列表中。

我们需要查看的定位系统的最后一部分是`GetAnchorPos()`函数。这个函数将根据之前在`IGUI`构造函数中看到的计算屏幕值和面板本身的大小返回面板的锚点位置：

```cpp
...
glm::vec2* IGUI::GetAnchorPos(GUIAnchorPos anchorPos, glm::vec4 bounds)
{
  switch (anchorPos)
  {
    case(GUIAnchorPos::TopRight):
    m_TR->y -= bounds.w;
    m_TR->x -= bounds.z;
    return m_TR;
    break;
    case(GUIAnchorPos::TopLeft):
    m_TL->y -= bounds.w;
    return m_TL;
    break;
    case(GUIAnchorPos::BottomRight):
    m_BR->x -= bounds.z;
    return m_BR;
    break;
    case(GUIAnchorPos::BottomLeft):
    return m_BL;
    break;
    case(GUIAnchorPos::Center):
    m_C->y -= bounds.w;
    return m_C;
    break;
  }
}
...
```

我们首先传入两个值。第一个是`GUIAnchorPos`，您可能还记得在`IGUIPanel.h`文件中定义`enum`类时在本章前面的部分。第二个是用四个向量对象描述的面板的边界。在函数内部，我们有一个 switch case 语句，我们使用它来确定要计算的锚点。

如果情况匹配`TopRight`枚举值，首先我们修改锚点的*y*轴值。我们这样做是因为我们使用左下角作为默认原点，所以我们需要修改这一点，使得左上角成为锚点的新原点。接下来，我们修改锚点的*x*轴值。我们这样做是因为我们需要将锚点从屏幕的右上角移动到面板对象的宽度。如果我们不修改*x*轴值，面板将绘制到屏幕右侧。

接下来，如果情况匹配`TopLeft`枚举值，我们修改锚点的*y*轴值。如前所述，我们这样做是为了考虑我们的坐标系的原点位于左下角。这次我们不需要修改*x*轴的值，因为当我们从左到右绘制时，我们的面板将出现在屏幕上。

如果情况匹配`BottomRight`枚举值，我们需要修改*x*轴的值。如前所述，我们需要将锚点向左移动面板的宽度，以确保面板绘制在屏幕上。这次我们不需要修改*y*轴的值，因为锚点将匹配默认坐标系的屏幕底部的*y*原点。

如果情况匹配`BottomLeft`枚举值，我们只需返回未修改的锚点，因为它与坐标系的默认原点匹配。

最后，如果情况匹配`Center`枚举值，我们只会修改*y*轴的值，因为我们只需要考虑默认原点位于屏幕左下角。构造函数中计算的*x*轴值将使面板向右移动，以正确地将其定位在屏幕中心。

这样就处理了我们的 GUI 系统的定位和锚点系统。我们现在有了一个坚实的框架，可以在本章的其余部分继续构建。接下来，我们将看看如何将输入控制添加到我们的 GUI 系统中。

# 添加控制逻辑

GUI 远不止是屏幕上所见的。在幕后还有逻辑运行，提供与对象交互所需的功能。处理鼠标移动到元素上时发生的情况，复选框被选中时发生的情况，或者按钮被点击时发生的情况，都是 GUI 输入系统的一部分。在本节中，我们将构建处理 GUI 鼠标输入所需的架构。

虽然我们可以以几种不同的方式实现处理 GUI 输入的系统，但我认为这是一个完美的机会，可以向您介绍我最喜欢的编程模式之一，即观察者模式。观察者是**四人帮**中最广为人知的模式之一。观察者如此常用，以至于 Java 有一个专门的核心库`java.util.Observer`，而 C#则将其纳入语言本身，以事件关键字的形式。

我认为解释观察者模式最简单的方法是，当您有对象执行另一个类或对象感兴趣的各种操作时，您可以*订阅* *事件*，并在这些对象执行其有趣功能时得到通知。很可能您在开发过程中已经见过并/或使用过观察者模式。事实上，我们在本书中已经见过它。SDL 库使用自己的观察者模式来处理输入。我们利用它来根据用户的输入执行任务。以下是我们用来处理游戏输入的 SDL 事件实现：

```cpp
SDL_Event event;
while (SDL_PollEvent(&event))
{
  m_game->OnSDLEvent(event);
}
```

我们要构建的东西可能有点基础，但它将让您了解如何为 GUI 实现输入系统，并且您可以希望熟悉一种灵活的模式，以便未来的开发。

首先，在`IGUIElement`头文件中，我们创建一个名为`GUIEvent`的新`enum`类：

```cpp
enum class GUIEvent
{
 HoverOver,
 Released,
 Clicked,
};
```

这个`enum`类定义了我们的 GUI 元素可以监听的不同类型的事件。接下来，在我们的`IGUIElement`类头文件中，我们需要添加一个完全虚拟的函数`OnNotify()`：

```cpp
virtual void OnNotify(IGUIElement& element, GUIEvent event) = 0;
```

这个函数将被每种元素类型覆盖，并在事件发生时调用。实现了这个函数的元素可以*监听*对它们重要的事件，并根据需要执行操作。`OnNotify()`接受两个参数：一个定义受影响的元素的`IGUIElement()`，以及事件类型。这两个参数将为我们提供确定如何处理发送的每个事件的所有所需信息。

让我们来看看我们的`IGUIButton()`对象类中`OnNotify()`的实现：

```cpp
void IGUIButton::OnNotify(IGUIElement & button, GUIEvent event)
{
   If(event == GUIEvent::HoverOver)
  {
   //Handle Hover
  }
}
```

在`IGUIButton::OnNotify`的实现中，我们可以监听传入的不同类型的事件。在这个例子中，我们正在检查传入的事件是否是`HoverOver`事件。如果是，我们会添加一个注释，说明当按钮悬停时我们需要执行的任何操作。这就是设置*listener*的全部内容。接下来，我们需要将我们的 GUI 输入系统连接到当前输入系统，并开始发送事件通知。让我们继续看看`IGUI`对象类中`CheckInput()`函数的实现：

```cpp
void IGUI::CheckInput(InputManager inputManager)
{
   float pointX = inputManager.GetMouseCoords().x;
   float pointY = inputManager.GetMouseCoords().y;
   for (auto &panel : m_GUIPanelsList) // access by reference to avoid                  
                                          copying
   {
    for (auto& object : panel->GetGUIElementList())
    {
    //Convert Y coordinate position to top upper left origin, y-down
     float convertedY =
     m_window.GetScreenHeight() -
     (object->GetPosition().y + object->GetBounds().w);
     if (pointX < object->GetPosition().x + (object->GetBounds().z) &&
     pointX >(object->GetPosition().x - (object->GetBounds().z)) &&
     pointY < convertedY + object->GetBounds().w &&
     pointY > convertedY - object->GetBounds().w)
    {
      object->OnNotify(*object, GUIEvent::HoverOver); 
      }
    }
  }
}
```

我们将逐步查看它。首先，我们从传入的`InputManager`对象中获取当前鼠标坐标，并将它们保存到临时变量中：

```cpp
void IGUI::CheckInput(InputManager inputManager)
{
float pointX = inputManager.GetMouseCoords().x;
float pointY = inputManager.GetMouseCoords().y;
```

接下来，我们需要使用嵌套的`for`循环来遍历 GUI 中的所有面板，依次遍历每个面板上附加的所有元素：

```cpp
for (auto &panel : m_GUIPanelsList) // access by reference to avoid copying
{
for (auto& object : panel->GetGUIElementList())
{
```

在嵌套循环内，我们将进行一个简单的*hit*测试，以查看我们是否在按钮的边界内。然而，首先，我们需要进行一个快速的计算。在本章的坐标和位置部分中，您可能还记得我们进行了一个转换，将锚点的*y*轴移动到左上角。现在我们需要做相反的操作，将元素位置的*y*轴转换回到左下角。我们之所以需要这样做，是因为鼠标光标的屏幕坐标系统与按钮位置相同：

```cpp
float convertedY = m_window.GetScreenHeight() -
                  (object->GetPosition().y + object->GetBounds().w);
```

循环中我们需要做的最后一件事是执行实际的*hit*或边界检查。为此，我们检查并查看鼠标光标的*x*轴值是否在按钮的屏幕区域内。我们还使用之前转换的*y*值在*y*轴上进行相同的检查。如果所有这些条件都满足，那么我们可以向元素发送一个`HoverOver`事件通知：

```cpp
if (pointX <element->GetPosition().x + (element->GetBounds().z) &&
pointX >(element->GetPosition().x - (element->GetBounds().z)) &&
pointY < convertedY + element->GetBounds().w &&
pointY > convertedY - element->GetBounds().w)
{
   object->OnNotify(*object, GUIEvent::HoverOver);
}
...
```

通过这样，我们虽然粗糙，但已经有了一个工作的事件系统。我们需要放置的最后一块拼图是将其连接到游戏引擎的当前输入处理系统。为此，我们在`ExampleScreen`类的`CheckInput()`函数中添加一行简单的代码，`m_gui->CheckInput(m_game->GetInputManager());`：

```cpp
void ExampleScreen::CheckInput(float deltaTime)
{
   SDL_Event event;
   while (SDL_PollEvent(&event))
   {
   m_game->OnSDLEvent(event);
   }
   ...
   m_gui->CheckInput(m_game->GetInputManager());
   ...
}
```

这就完成了本章示例的逻辑实现。肯定还有重构和调优的空间，但这应该为您提供了一个扩展的良好起点。我建议您继续进行下一步，并添加更多功能，甚至可能添加新的元素来使用。在下一节中，我们将通过向我们的 GUI 系统添加渲染并最终在屏幕上绘制示例来结束本章。

# 渲染 GUI

有了所有的定位和输入逻辑，我们现在可以通过实现一些基本的渲染来完成我们的 GUI 系统。好消息是，我们在书中前面已经建立了一个强大的主要渲染基础设施。我们将利用这个基础设施在屏幕上渲染我们的 GUI。基本上，在渲染 GUI 时有两种选择。您可以将 GUI 渲染到纹理中，然后将创建的纹理混合到最终绘制的场景中。另一个选择是在每一帧中将所有内容作为几何体渲染在场景的顶部。两者都有各自的问题，但我认为在大多数情况下，创建纹理并混合该纹理会比将 GUI 元素渲染为几何体要慢。

为了保持事情稍微简单，并更专注于实现，我们从一个更简单的方法开始，分别渲染每个元素。当然，如果 GUI 中有大量元素，这并不是最友好的性能渲染方式。在我们的示例中，我们不会有大量元素，如果您正在构建类似开始游戏/菜单 GUI 的东西，当前形式的解决方案将是完全足够的。注意您的帧率，如果注意到下降，那么很可能是有太多的绘制调用。

我们可以采用与渲染模型时相同的方法来处理我们的解决方案，只是有些细微差异。我们将再次使用着色器来绘制几何图形，因为这将为我们提供大量控制和执行任何混合、蒙版、图案和效果的能力。对于我们的 GUI 示例，我们将重用前几章的纹理顶点和片段着色器。在下一章中，我们将深入探讨高级着色器和绘图技术。

所以，让我们深入实现。将这些添加到`IGUI.h`文件中：

```cpp
std::unique_ptr<Camera2D> m_camera = nullptr; 

        std::unique_ptr<ShaderManager> m_textureProgram = nullptr; 
        std::unique_ptr<SpriteBatch> m_spriteBatch = nullptr; 

```

然后在`IGUI`对象的构造函数中添加这个：

```cpp
IGUI::IGUI(Window& window) : m_window(window)
{
   m_camera = std::make_unique<Camera2D>();
   ...
   m_textureProgram = std::make_unique<BookEngine::ShaderManager>();
   m_spriteBatch = std::make_unique<BookEngine::SpriteBatch>();
}
```

在这里，我们指定了一个着色器纹理程序、一个精灵批处理和一个 2D 相机。这个相机与我们在本书前面创建的 3D 版本略有不同。我不会深入讨论 2D 相机，因为它略微超出了本章的范围，但我会提到主要的变化是我们正在为 2D 绘图构建正交矩阵。我们为每个 GUI 实例提供自己的着色器、相机和精灵批处理。最终设置将由实例来处理。

`ExampleGUI`是我们示例中`IGUI`类的实现。看一下`OnInit()`函数，我们可以看到这些资源的设置：

```cpp
void ExampleGUI::OnInit()
{
m_textureProgram->CompileShaders(
                        "Shaders/textureShading.vert",
                        "Shaders/textureShading.frag");
m_textureProgram->AddAttribute("vertexPosition");
m_textureProgram->AddAttribute("vertexColor");
m_textureProgram->AddAttribute("vertexUV");
m_textureProgram->LinkShaders();
m_spriteBatch->Init();
m_camera->Init(m_window.GetScreenWidth(), 
               m_window.GetScreenHeight());
m_camera->SetPosition(glm::vec2(
                                m_window.GetScreenWidth() * 0.5f, 
                                m_window.GetScreenHeight()* 0.5f));
panel = new BookEngine::IGUIPanel(
                                glm::vec4(0, 0, 150, 500),
                                *GetAnchorPos(
                                   BookEngine::GUIAnchorPos:BottomLeft,
                                    glm::vec4(0, 0, 150, 500)
                                  ),
                                  glm::vec2(0,0));
AddGUIPanel(*panel);

      BookEngine::GLTexture texture
    =BookEngine::ResourceManager::GetTexture("Textures/button.png");

button = new BookEngine::IGUIButton(
    glm::vec4(0, 0, 100, 50),
    glm::vec2(10, -10),"My Button", &texture,
    new BookEngine::SpriteFont("Fonts/Impact_Regular.ttf", 72),
       glm::vec2(0.2f), panel);

       AddGUIElement (*button);
}
```

我们将逐个分解。首先，我们需要编译我们 GUI 所需的`Shaders`，所以我们添加着色器所需的属性，最后将它们链接以供使用。这应该很熟悉：

```cpp
m_textureProgram->CompileShaders(
"Shaders/textureShading.vert",
"Shaders/textureShading.frag");
m_textureProgram->AddAttribute("vertexPosition");
m_textureProgram->AddAttribute("vertexColor");
m_textureProgram->AddAttribute("vertexUV");
m_textureProgram->LinkShaders();
Next, we call Init on the sprite batch for the GUI instance:
m_spriteBatch->Init();
```

然后我们在 2D 相机实例上调用`Init`，传递屏幕宽度和高度。在`Init`之后，我们将相机的位置设置为屏幕中间，通过将屏幕的高度和宽度值除以 2：

```cpp
m_camera->Init(m_window.GetScreenWidth(), 
               m_window.GetScreenHeight());
m_camera->SetPosition(glm::vec2(
                       m_window.GetScreenWidth() * 0.5f,
                       m_window.GetScreenHeight()* 0.5f));
```

现在我们有了着色器程序、精灵批处理和相机设置，我们继续创建 GUI 元素。首先是面板元素，我们使用之前在本章创建的架构来创建它。我们将其锚点设置为屏幕的左下角。面板创建完成后，我们通过调用类继承的`AddGUIPanel`函数将其添加到 GUI 实例中：

```cpp
panel = new BookEngine::IGUIPanel(glm::vec4(0, 0, 150, 500),
                                 *GetAnchorPos(
                                 BookEngine::GUIAnchorPos:BottomLeft,                                  
                                 glm::vec4(0, 0, 150, 500)
                                 ),
  glm::vec2(0,0));
  AddGUIPanel(*panel);
```

面板创建并添加到 GUI 实例的面板列表后，我们将一个按钮添加到该面板。为此，我们首先创建一个临时变量来保存我们想要为此按钮加载的纹理。然后我们创建按钮本身。我们再次使用本章前面构建的结构。我们传入标签`My Button`和刚刚加载的纹理。完成后，我们调用`AddGUIElement()`函数并将按钮添加到面板：

```cpp
BookEngine::GLTexture texture = BookEngine::ResourceManager::GetTexture("Textures/button.png");
button = new BookEngine::IGUIButton(
           glm::vec4(0, 0, 100, 50),
           glm::vec2(10, -10),
           "My Button",
           &texture,
           new BookEngine::SpriteFont("Fonts/Impact_Regular.ttf", 72),
glm::vec2(0.2f), panel);
AddGUIElement (*button);
```

现在我们的元素已经就位，渲染组件已经创建并设置好，我们可以为 GUI 系统最终确定渲染流程。为了做到这一点，我们将回归到我们在对象中创建的继承结构。要开始绘制调用链，我们从`ExampleGUI`类和它的`Draw()`函数实现开始：

```cpp
void ExampleGUI::Draw() 
{ 

    ... 

    m_textureProgram->Use(); 

    ... 

    m_spriteBatch->Begin(); 

    //Draw all of the panels 
    for (auto const&panel : m_GUIPanelsList) 
    { 
        panel->Draw(*m_spriteBatch); 
    } 

    m_spriteBatch->End(); 
    m_spriteBatch->BatchRender(); 
    m_textureProgram->UnUse(); 

} 
```

关注我们 GUI 实现的一个重要方面，我们首先在`Draw()`函数中指定我们在渲染 GUI 元素时要使用的着色器程序。接下来，我们启动将用于 GUI 元素的精灵批次。然后，在精灵批次的开始和结束之间，我们使用一个`for`循环来遍历 GUI 面板列表中的所有面板，并调用其`Draw()`函数的实现。一旦`for`循环完成，我们就结束了精灵批次，调用`BatchRender()`方法来渲染批次中的所有对象，最后通过在着色器程序上调用`UnUse()`方法来关闭函数。

让我们在绘制链中再往下一级，并查看 IGUIPanel 的 Draw 函数实现：

```cpp
void IGUIPanel::Draw(SpriteBatch& spriteBatch) 
    { 
spriteBatch.Draw(glm::vec4(m_Pos.x,  
m_Pos.y, 
m_panelWidth,  
m_panelHeight), 
 glm::vec4(0,0,1,1), 
BookEngine::ResourceManager::GetTexture( 
"Textures/background.png").id,  
-0.1f,  
ColorRGBA8(0,0,0,75) 
); 

        for (auto const&element : m_GUIElementList) 
        { 
            element->Draw(spriteBatch); 
        } 
    } 
```

在`IGUIPanel::Draw()`函数中，我们首先将面板本身添加到从调用对象传入的精灵批次中。这将绘制一个略带不透明的黑色背景。理想情况下，您希望使用于背景的纹理成为一个非硬编码的值，并允许为每个实例进行设置。在我们将面板添加到用于绘制的精灵批次后，我们再次使用`for`循环来遍历面板元素列表中的每个元素，并调用其`Draw()`函数的实现。这实际上将其使用推到了绘制链中的下一层。

对于`IGUIElement`类，我们只需创建一个纯虚函数，继承该函数的元素将不得不实现：

```cpp
virtual void Draw(SpriteBatch& spriteBatch) = 0;
```

这意味着我们现在可以进入我们绘制链示例中的最后一个链接，并查看`IGUIButton::Draw()`函数的实现：

```cpp
void IGUIButton::Draw(SpriteBatch& spriteBatch)   { 
        ... 

        spriteBatch.Draw(glm::vec4(m_position.x, 
 m_position.y,  
m_bounds.z,  
m_bounds.w),  
uvRect,  
m_texture.id,  
0.0f,  
ColorRGBA8(255, 255, 255, 255)); 

        char buffer[256]; 
        m_spriteFont->Draw(spriteBatch,  
buffer,  
glm::vec2( 
m_position.x + (m_bounds.z * 0.5f),  
(m_position.y + (m_bounds.w * 0.5f)) - ((m_spriteFont->GetFontHeight() * m_fontScale.y) * 0.5f) 
), 
                            m_fontScale,  
0.2f,  
BookEngine::ColorRGBA8(255, 255, 255, 255), 
Justification::MIDDLE);         
    } 

```

再次，这些函数的实现并不太复杂。我们将元素添加到由调用对象传入的精灵批次中以进行绘制。这样做的效果是，所有面板及其元素将被添加到单个 GUI 实例的精灵批次中，这将比每个面板和对象依次绘制自身要更高效。`Draw()`函数中的最后一个代码块是对 Sprite Font 实例的`Draw()`方法的调用。我不会详细介绍 Sprite Font 类的工作原理，因为这超出了本章的范围，但请查看代码文件以了解其内部工作原理。`SpriteFont`类的作用与`Sprite`类类似，只是它提供了在屏幕上绘制字体/文本的方法。在这个例子中，我们使用它来绘制按钮的标签。

这就结束了绘制链。现在我们只需要将 GUI 的头部`Draw()`调用连接到主游戏的`Draw()`调用。为此，在`ExampleScreen`类的`Draw()`函数中添加一行调用 GUI 实例的`Draw()`方法：

```cpp
void EditorScreen::Draw()
{ 
... 
    m_gui->Draw(); 
} 

```

现在，我很高兴地说，我们已经有了一个简单但完整的工作 GUI 系统。您可以运行示例演示来查看已完成的 GUI 运行情况。如果您想要查看面板如何受到每个定义的锚点的影响，您只需要在`ExampleGUI`类中设置面板时更改`BookEngine::GUIAnchorPos`的值：

```cpp
 panel = new BookEngine::IGUIPanel(glm::vec4(0, 0, 150, 500), 
*GetAnchorPos( 
BookEngine::GUIAnchorPos::BottomRight, 
glm::vec4(0, 0, 150, 500) 
), 
 glm::vec2(0,0)); 
```

以下是 GUI 在运行中的屏幕截图，其锚点已更改为`BottomLeft`、`BottomRight`、`TopLeft`、`TopRight`和`Center`：

`BottomRight`的屏幕截图如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/0595a630-669f-412c-adb4-9e951d649152.png)

`BottomLeft`的屏幕截图如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/8ee5b8ea-aa35-454f-8e9a-c4fcf8a37907.png)

`TopLeft`的屏幕截图如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/ebbf1359-bb61-446e-9caa-461cc74cab06.png)

`TopRight`的屏幕截图如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/770ecc8b-c2d8-4e5f-bfca-eed425cd420c.png)

`Center`的屏幕截图如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/14a196c6-26aa-4e71-a784-45126f8d26d3.png)

# 总结

在本章中，我们涵盖了大量信息。我们讨论了创建 GUI 所需的不同方面。我们深入探讨了工作 GUI 背后的核心架构。我们开发了一个面板和元素架构，包括用于控制定位的锚点。我们使用“观察者”设计模式实现了用户输入结构，并通过编写渲染管道来显示屏幕上的 GUI 元素。在下一章中，我们将深入探讨游戏开发中使用的一些高级渲染技术。
