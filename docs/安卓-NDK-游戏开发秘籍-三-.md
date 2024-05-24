# 安卓 NDK 游戏开发秘籍（三）

> 原文：[`zh.annas-archive.org/md5/713F9F8B01BD9DC2E44DADEE702661F7`](https://zh.annas-archive.org/md5/713F9F8B01BD9DC2E44DADEE702661F7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：跨平台音频流

|   | *尝试关闭你最喜欢的游戏中的声音。* |   |
| --- | --- | --- |
|   | --*维克多·拉蒂波夫* |

本章我们将介绍以下内容：

+   初始化 OpenAL 并播放.wav 文件

+   抽象基本音频组件

+   流式声音

+   解码 Ogg Vorbis 文件

+   使用 ModPlug 解码跟踪器音乐

# 引言

我们在寻找一种真正可移植的实现方案，以在桌面电脑和移动设备上进行声音播放。我们建议使用 OpenAL 库，因为它在桌面端已经相当成熟，使用它将使得将现有游戏移植到 Android 更加容易。在本章中，我们将组织一个小型的多线程声音流媒体库。

音频播放本质上是一个异步过程，因此解码和控制声音硬件应该在单独的线程上完成，并从其他专用线程进行控制。例如，当玩家按下开火按钮，或者在街机游戏中一个角色撞击地面时，我们可能只是要求系统开始播放一个音频文件。在游戏中，这个操作的延迟通常不是很重要。

从数字角度来看，单声道或单声道声音（简称 mono），不过是表示连续信号的长时间一维数组。立体声或多声道声音由几个声道表示，并以交错数组的形式存储，其中一个声道的采样紧接着另一个声道的采样，依此类推。OpenAL 期望我们以一系列缓冲区的形式提交这些数据。OpenAL 库的主要概念包括设备、上下文、监听器、音频源和声音缓冲区：

![简介](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_05_1.jpg)

在虚拟环境中产生的声音经过一系列滤波器处理后，通过扬声器播放。本章涵盖的内容将允许你为你的游戏创建一个可移植的音频子系统。

# 初始化 OpenAL 并播放.wav 文件

在这个食谱中，我们展示了播放未压缩音频文件的最简单示例，这些文件采用**PCM**格式（**脉冲编码调制**，[`en.wikipedia.org/wiki/Pulse-code_modulation`](http://en.wikipedia.org/wiki/Pulse-code_modulation)）。这个示例只是在无限循环中播放单个文件。我们将创建一个单一设备、一个单一设备上下文和一个音频源。所有这些都在一个专用线程中完成，但我们不应该担心多线程问题，因为 OpenAL 函数是保证线程安全的。

## 准备工作

OpenAL 库的源代码和构建脚本可以在`0_OpenAL`文件夹中找到，本章的每个示例都包含预编译的静态库。对于 Windows，我们使用动态链接与 OpenAL。关于如何从 Android `.apk`包中加载文件的说明可以在第四章，*组织虚拟文件系统*中找到。此配方的完整示例源代码可以在`0_AL_On_Android`文件夹中找到。

## 如何操作...

1.  `SoundThread`类，我们在这个类中实现了实际播放，如下所示：

    ```kt
    class SoundThread: public iThread
    {
    ```

1.  首先，我们声明 OpenAL 音频设备和设备上下文的句柄：

    ```kt
      ALCdevice*  FDevice;
      ALCcontext* FContext;
    ```

1.  然后，我们声明 OpenAL 音频源和缓冲区的句柄：

    ```kt
      ALuint FSourceID;
      ALuint FBufferID;
    ```

1.  `Run()`成员函数执行所有工作，包括初始化、反初始化以及将音频数据提交到 OpenAL：

    ```kt
      virtual void Run()
      {
    ```

1.  我们初始化指向 OpenAL 函数的指针：

    ```kt
        LoadAL();
    ```

1.  然后，我们创建设备和设备上下文：

    ```kt
        FDevice = alcOpenDevice( NULL );
        FContext = alcCreateContext( FDevice, NULL );
    ```

1.  最后，我们将新创建的设备上下文选为当前上下文：

    ```kt
        alcMakeContextCurrent( FContext );
    ```

1.  现在，我们开始创建音频源：

    ```kt
        alGenSources( 1, &FSourceID );
    ```

1.  我们设置一个常量最大播放音量为`1.0`，在 OpenAL 中这被称为**增益**：

    ```kt
        alSourcef( FSourceID, AL_GAIN, 1.0f );
    ```

1.  为了听到声音，我们必须加载包含声音数据的文件：

    ```kt
        clPtr<iIStream> Sound = g_FS->CreateReader("test.wav");
    ```

1.  我们使用内存映射文件，并询问 iStream 对象关于文件大小：

    ```kt
        int DataSize = (int)Sound->GetSize();
        const ubyte* Data = Sound->MapStream();
    ```

1.  为了避免处理完整的**RIFF WAVE**文件格式，我们准备了一个包含单个未压缩音频数据块的特定文件；此数据的格式是 22 kHz 单声道 16 位声音。我们传递`Data+sizeof(sWAVHeader)`作为音频数据，音频数据的大小显然是`DataSize-sizeof(sWAVHeader)`：

    ```kt
        PlayBuffer( Data + sizeof( sWAVHeader ),
        DataSize - sizeof( sWAVHeader ));
    ```

1.  然后，我们在自旋循环中调用`IsPlaying()`函数，以检测 OpenAL 何时停止播放声音：

    ```kt
        while ( IsPlaying() ) {}
    ```

1.  一旦声音播放完成，我们就删除我们创建的所有对象：

    ```kt
        alSourceStop( FSourceID );
        alDeleteSources( 1, &FSourceID );
        alDeleteBuffers( 1, &FBufferID );
        alcDestroyContext( FContext );
        alcCloseDevice( FDevice );
    ```

1.  最后，在 Windows 上卸载 OpenAL 库：

    ```kt
        UnloadAL();
    ```

1.  在 Android 上，释放分配的资源并释放音频设备非常重要。否则，音频会在后台继续播放。为了避免在这个小示例中编写 Java 代码，我们只需通过`exit()`调用终止本地活动：

    ```kt
        exit( 0 );
      }
    ```

1.  上面的代码使用`IsPlaying()`函数来检查音频源是否忙碌：

    ```kt
      bool IsPlaying()
      {
        int State;
        alGetSourcei( FSourceID, AL_SOURCE_STATE, &State );
        return State == AL_PLAYING;
      }
    ```

1.  `PlayBuffer()`函数将音频数据提供给音频源：

    ```kt
      void PlayBuffer(const unsigned char* Data, int DataSize)
      {
        alGenBuffers( 1, &FBufferID );
        alBufferData( FBufferID, AL_FORMAT_MONO16,
        Data, DataSize, 22050 );
        alSourcei( FSourceID, AL_BUFFER, FBufferID );
        alSourcePlay( FSourceID );
      }
    };
    ```

1.  上面的代码使用`sWAVHeader`结构的大小来确定音频数据的偏移量：

    ### 注意

    `sWAVHeader`的结构字段对齐应设置为`1`。我们的声明与 Android NDK 和 MinGW 的 Clang 和 GCC 编译器兼容。对于 VisualStudio 使用#pragma pack。

    ```kt
    struct __attribute__((packed,aligned(1))) sWAVHeader
    {
      unsigned char    RIFF[4];
      unsigned int     Size;
      unsigned char    WAVE[4];
      unsigned char    FMT[4];
      unsigned int     SizeFmt;
      unsigned short   FormatTag;
      unsigned short   Channels;
      unsigned int     SampleRate;
      unsigned int     AvgBytesPerSec;
      unsigned short   nBlockAlign;
      unsigned short   nBitsperSample;
      unsigned char    Reserved[4];
      unsigned int     DataSize;
    };
    ```

之后我们重用这个结构来加载`.wav`文件。

## 工作原理...

首先，我们声明保存虚拟文件系统和`SoundThread`对象的的全局变量：

```kt
clPtr<FileSystem> g_FS;
SoundThread g_Sound;
```

我们创建常规的应用程序模板，并在`OnStart()`回调函数中启动一个线程来初始化 OpenAL 库：

```kt
void OnStart( const std::string& RootPath )
{
  …
  g_FS = new FileSystem();
  g_FS->Mount( "." );
#if defined(ANDROID)
  g_FS->Mount( RootPath );
  g_FS->AddAliasMountPoint( RootPath, "assets" );
#endif
  g_Sound.Start( iThread::Priority_Normal );
}
```

## 另请参阅

+   第二章，*移植通用库*

+   第四章《组织虚拟文件系统》中的*实现可移植的内存映射文件*食谱

# 抽象基本音频组件

在上一个食谱中，我们学习了如何初始化 OpenAL 以及如何播放未压缩的`.wav`文件。在这里，我们介绍`AudioSource`和`AudioThread`类，它们帮助我们管理初始化过程。

## 准备就绪

查看补充材料中的示例`0_AL_On_Android`，以了解 OpenAL 的基本概念。

## 如何操作…

1.  让我们仔细地将 OpenAL 的初始化移动到另一个名为`AudioThread`的线程中：

    ```kt
    class AudioThread: public iThread
    {
    public:
      AudioThread():
        FDevice( NULL ),
        FContext( NULL ),
        FInitialized( false ) {}
      virtual ~AudioThread() {}

      virtual void Run()
      {
    ```

1.  `Run()`方法开头的代码执行默认 OpenAL 设备的初始化并创建音频上下文：

    ```kt
        if ( !LoadAL() ) { return; }

        FDevice = alcOpenDevice( NULL );
        FContext = alcCreateContext( FDevice, NULL );
        alcMakeContextCurrent( FContext );
    ```

1.  我们设置一个标志，告诉其他线程它们是否可以使用我们的音频子系统：

    ```kt
        FInitialized = true;
    ```

1.  然后，我们进入一个无限循环，调用`Env_Sleep()`函数，其源代码如下所述，以避免使用 CPU 的 100%利用率：

    ```kt
        FPendingExit = false;
        while ( !IsPendingExit() ) { Env_Sleep( 100 ); }
    ```

    ### 注意

    在此示例中，我们使用了 100 毫秒的固定值将线程置于睡眠模式。在处理音频时，根据缓冲区大小和采样率计算睡眠延迟很有用。例如，一个包含 16 位单声道样本的`65535`字节的缓冲区，在`44100`赫兹的采样率下，大约可以播放*65535 / (44100 × 16 / 8) ≈ 0.7*秒的音频。立体声播放将这个时间减半。

1.  最后，我们释放 OpenAL 对象：

    ```kt
        alcDestroyContext( FContext );
        alcCloseDevice( FDevice );
        UnloadAL();
      }
    ```

1.  声明其余部分简单包含了所有必需的字段和初始化标志：

    ```kt
      bool FInitialized;
    private:
      ALCdevice*     FDevice;
      ALCcontext*    FContext;
    };
    ```

1.  代码中使用的`Env_Sleep()`函数只是让线程在给定毫秒数内不活跃。它在 Windows 中使用`Sleep()`系统调用，在 Android 中使用`usleep()`函数实现：

    ```kt
    void Env_Sleep( int Milliseconds )
    {
    #if defined _WIN32
      Sleep( Milliseconds );
    #else
      usleep( static_cast<useconds_t>( Milliseconds ) * 1000 );
    #endif
    }
    ```

1.  仅播放`.wav`文件还不够，因为我们想要支持不同的音频格式。因此，我们必须将音频播放和文件格式的实际解码分为两个独立的实体。我们准备引入`iWaveDataProvider`类，其子类作为我们音频播放类的数据源：

    ```kt
    class iWaveDataProvider: public iObject
    {
    public:
      iWaveDataProvider(): FChannels( 0 ),
        FSamplesPerSec( 0 ),
        FBitsPerSample( 0 ) {}
    ```

1.  这个类的主要例程允许访问解码的音频数据：

    ```kt
      virtual ubyte* GetWaveData() = 0;
      virtual size_t GetWaveDataSize() const = 0;
    ```

1.  下面是如何从该提供者获取内部 OpenAL 音频格式标识符的方法：

    ```kt
      ALuint GetALFormat() const
      {
        if ( FBitsPerSample == 8 )
           {
          return (FChannels == 2) ?
            AL_FORMAT_STEREO8  : AL_FORMAT_MONO8;
           }
        else if ( FBitsPerSample == 16)
           {
          return (FChannels == 2) ?
            AL_FORMAT_STEREO16 : AL_FORMAT_MONO16;
           }
        return AL_FORMAT_MONO8;
      }
    ```

1.  同时，我们在这里存储有关音频格式的信息：

    ```kt
      int FChannels;
      int FSamplesPerSec;
      int FBitsPerSample;
    };
    ```

1.  如我们所知，必须创建一个音频源以产生声音。这一功能在`AudioSource`类中实现，该类封装了前一个食谱中的 OpenAL 函数调用。这个类使用`iWaveDataProvider`实例作为音频数据源：

    ```kt
    class AudioSource: public iObject
    {
    public:
    ```

1.  构造函数只是创建了一个 OpenAL 源句柄并设置了默认参数：

    ```kt
      AudioSource(): FWaveDataProvider( NULL )
      {
        alGenSources( 1, &FSourceID );
        alSourcef( FSourceID, AL_GAIN,    1.0 );
        alSourcei( FSourceID, AL_LOOPING, 0   );
      }
    ```

1.  析构函数停止播放并执行清理工作：

    ```kt
      virtual ~AudioSource()
      {
        Stop();
        FWaveDataProvider = NULL;
        alDeleteSources( 1, &FSourceID );
        alDeleteBuffers( 1, &FBufferID );
      }
    ```

1.  `Play()`方法将 OpenAL 源切换到播放状态：

    ```kt
      void Play()
      {
        if ( IsPlaying() ) { return; }
        alSourcePlay( FSourceID );
      }
    ```

1.  `Stop()`方法将 OpenAL 源切换到停止状态。停止后只能从声音缓冲区的开始处恢复播放：

    ```kt
      void Stop()
      {
        alSourceStop( FSourceID );
      }
    ```

1.  `IsPlaying()`方法检查源是否正在播放音频。实现来自之前的食谱：

    ```kt
      bool IsPlaying() const
      {
        int State;
        alGetSourcei( FSourceID, AL_SOURCE_STATE, &State );
        return State == AL_PLAYING;
      }
    ```

1.  一个小的`SetVolume()`方法改变源的播放音量。接受的浮点值范围是`0.0…1.0`：

    ```kt
      void SetVolume( float Volume )
      {
        alSourcef( FSourceID, AL_GAIN, Volume );
      }
    ```

1.  主例程，即向音频源提供数据的`BindWaveform()`。这个函数存储了对数据提供者的智能指针，并生成了一个 OpenAL 缓冲区对象：

    ```kt
      void BindWaveform( clPtr<iWaveDataProvider> Wave )
      {
        FWaveDataProvider = Wave;
        if ( !Wave ) return;

        alGenBuffers( 1, &FBufferID );
        alBufferData( FBufferID,
          Wave->GetALFormat(),
          Wave->GetWaveData(),
          (int)Wave->GetWaveDataSize(),
          Wave->FSamplesPerSec );
        alSourcei( FSourceID, AL_BUFFER, FBufferID );
      }
    ```

1.  `AudioSource`类的私有部分包含对音频数据提供者的引用以及内部 OpenAL 源和缓冲区句柄：

    ```kt
    private:
      clPtr<iWaveDataProvider> FWaveDataProvider;
      ALuint FSourceID;
      ALuint FBufferID;
    };
    ```

1.  为了能够从文件中读取声音，我们在`WavProvider`类中实现了`iWaveDataProvider`接口：

    ```kt
    class WavProvider: public iWaveDataProvider
    ```

1.  这个类包含的唯一字段是一个指向包含文件数据的`Blob`对象的智能指针：

    ```kt
      clPtr<Blob> FRawData;
    ```

1.  一个简单的脉冲编码调制`.wav`文件由开头的`sWAVHeader`结构和音频数据组成，可以直接输入到 OpenAL 音频源中。`WavProvider`类的构造函数提取有关音频数据的信息：

    ```kt
      WavProvider( const clPtr<clBlob>& blob )
      {
        FRawData = blob;
        sWAVHeader H = *(sWAVHeader*)FRawData->GetData();

        const unsigned short FORMAT_PCM = 1;
        FChannels      = H.Channels;
        FSamplesPerSec = H.SampleRate;
        FBitsPerSample = H.nBitsperSample;
      }
    ```

1.  析构函数是空的，因为我们的`Blob`对象被包装成了一个智能指针：

    ```kt
      virtual ~WavProvider() {}
    ```

1.  `iWaveDataProvider`接口很简单，这里我们只实现两个成员函数。`GetWaveData()`返回指向音频数据的指针：

    ```kt
      virtual ubyte* GetWaveData()
      {
        return (ubyte*)FRawData->GetDataConst() +
          sizeof( sWAVHeader );
      }
    ```

1.  `GetWaveDataSize()`方法从总文件大小中减去文件头大小：

    ```kt
      virtual size_t GetWaveDataSize() const
      {
        return FRawData->GetSize() - sizeof( sWAVHeader );
      };
    ```

现在我们完成了音频播放和解码。

## 它是如何工作的…

现在我们可以演示如何一起使用所有音频类。像往常一样，我们创建一个空的应用程序模板，可以在`1_AL_Abstraction`文件夹中找到。

为了能够使用 OpenAL，我们必须声明一个全局`AudioThread`实例：

```kt
AudioThread g_Audio;
```

我们在`OnStart()`回调函数中启动这个线程：

```kt
g_Audio.Start( iThread::Priority_Normal );
```

在这个例子中，我们实现了`SoundThread`类，其`Run()`方法处理所有播放。在这个线程上，我们必须等待`g_Audio`初始化完成：

```kt
while ( !g_Audio.FInitialized ) {}
```

现在我们可以创建音频源：

```kt
clPtr<AudioSource> Src = new AudioSource();
```

最后，我们需要创建一个`WavProvider`对象，它解码音频文件，将其附加到`Src`源，开始播放并等待其完成：

```kt
clPtr<Blob> Data = LoadFileAsBlob("test.wav");
Src->BindWaveform( new WavProvider( Data ) );
Src->Play();
while ( Src->IsPlaying() ) {}
```

音频播放完成后，我们将`Src`指针重置为`NULL`，并向`g_Audio`线程发送终止信号：

```kt
Src = NULL;
g_Audio.Exit(true);
```

为了获取`Data`对象，我们必须实现以下函数，它将文件内容读取到内存块中：

```kt
clPtr<Blob> LoadFileAsBlob( const std::string& FName )
{
  clPtr<iIStream> input = g_FS->CreateReader( FName );
  clPtr<Blob> Res = new Blob();
  Res->CopyMemoryBlock( input->MapStream(), input->GetSize() );
  return Res;
}
```

我们使用全局初始化的`FileSystem`实例，即`g_FS`对象。请注意，在 Android OS 上，我们不能使用标准路径，因此采用我们的虚拟文件系统实现。

## 还有更多…

我们可以实施一些辅助程序，以简化`AudioSource`类的使用。第一个有用的例程是源暂停。OpenAL 提供了`alSourcePause()`函数，但这还不够，因为我们必须控制所有正在播放的未排队缓冲区。此时，这个未排队并不重要，因为我们只有一个缓冲区，但是当我们开始流式传输声音时，我们必须注意缓冲区队列。以下代码应该添加到`AudioSource`类以实现暂停：

```kt
void Pause()
{
  alSourcePause( FSourceID );
  UnqueueAll();
}
void UnqueueAll()
{
  int Queued;
  alGetSourcei( FSourceID, AL_BUFFERS_QUEUED, &Queued );

  if ( Queued > 0 )
  alSourceUnqueueBuffers(FSourceID, Queued, &FBufferID);
}
```

对于无限声音循环，我们可以在`AudioSource`类中实现`LoopSound()`方法：

```kt
void LoopSound( bool Loop )
{
  alSourcei( FSourceID, AL_LOOPING, Loop ? 1 : 0);
}
```

安卓操作系统运行在多种硬件架构上，这可能导致在读取`.wav`文件时出现一些额外的困难。如果我们运行的 CPU 具有大端架构，我们就必须交换`sWAVHeader`结构字段中的字节。修改后的`WavProvider`类的构造函数如下所示：

```kt
WavProvider(clPtr<Blob> source)
{
  FRawData = source;
  sWAVHeader H = *(sWAVHeader*)(FRawData->GetData());
#if __BIG_ENDIAN__
  Header.FormatTag = SwapBytes16(Header.FormatTag);
  Header.Channels  = SwapBytes16(Header.Channels);
  Header.SampleRate = SwapBytes32(Header.SampleRate);
  Header.DataSize   = SwapBytes32(Header.DataSize);
  Header.nBlockAlign = SwapBytes16(Header.nBlockAlign);
  Header.nBitsperSample = SwapBytes16(Header.nBitsperSample);
```

大端内存字节顺序要求 16 位值的低字节和高字节互换：

```kt
  if ( (Header.nBitsperSample == 16) )
  {
    clPtr<Blob> NewBlob = new clBlob();
    NewBlob->CopyBlob( FRawData.GetInternalPtr() );
    FRawData = NewBlob;
    unsigned short* Ptr =
      (unsigned short*)FRawData->GetData();
    for ( size_t i = 0 ; i != Header.DataSize / 2; i++ )
    {
      *Ptr = SwapBytes16(*Ptr);
      Ptr++;
     }
  }
#endif
  FChannels      = H.Channels;
  FSamplesPerSec = H.SampleRate;
  FBitsPerSample = H.nBitsperSample;
}
```

在这里，我们使用 GCC 编译器提供的`__BIG_ENDIAN__`预处理器符号来检测大端 CPU。两个`SwapBytes()`函数改变无符号字和双字的字节顺序：

```kt
unsigned short SwapBytes16( unsigned short Val )
{
  return (Val >> 8) | ((Val & 0xFF) << 8);
}
unsigned int SwapBytes32( unsigned int Val )
{
  return	(( Val & 0xFF ) << 24 ) |
    (( Val & 0xFF00   ) <<  8 ) |
    (( Val & 0xFF0000 ) >>  8 ) |
    (  Val >> 24);
}
```

## 另请参阅

+   *解码 Ogg Vorbis 文件*

# 流式声音

我们已经学会了如何播放短音频样本，现在我们准备组织声音流。本食谱解释了如何组织一个缓冲区队列，以允许即时声音生成和流式传输。

## 准备工作

我们假设读者已经熟悉我们在上一个食谱中描述的`AudioSource`和`iWaveDataProvider`类。

## 如何操作...

1.  首先，我们用额外的`IsStreaming()`方法丰富`iWaveDataProvider`，该方法表示应该以小块的方式从这个提供者读取数据，以及`StreamWaveData()`，它实际读取单个块：

    ```kt
    class iWaveDataProvider: public iObject
      …
      virtual bool IsStreaming() const { return false; }
      virtual int  StreamWaveData( int Size ) { return 0; }
      …
    };
    ```

1.  接下来，我们编写一个派生类，其中包含一个用于解码或生成的声音数据的中间缓冲区。它没有实现`StreamWaveData()`，但实现了`GetWaveData()`和`GetWaveDataSize()`方法：

    ```kt
    class StreamingWaveDataProvider: public iWaveDataProvider
    {
    public:
      virtual bool IsStreaming() const { return true; }

      virtual ubyte* GetWaveData() { return (ubyte*)&FBuffer[0]; }
      virtual size_t GetWaveDataSize() const { return FBufferUsed; }

      std::vector<char> FBuffer;
      int               FBufferUsed;
    };
    ```

1.  `FBufferUsed`字段保存了`FBuffer`向量中使用的字节数。现在我们修改`AudioSource`类以支持我们的新流式数据提供者。我们不希望在播放过程中出现裂缝或中断，因此我们使用缓冲区队列代替在单块声音播放中使用的单个缓冲区。为此，我们首先声明一个缓冲区计数器和缓冲区 ID 数组：

    ```kt
    class AudioSource: public iObject
    {
    private:
      unsigned int FSourceID;
      int          FBuffersCount;
      unsigned int FBufferID[2];
    ```

1.  我们将`LoopSound()`、`Stop()`、`Pause()`、`IsPlaying()`和`SetVolume()`成员函数，构造函数和析构函数的实现保持不变。现在`BindWaveform()`方法在关联的波形数据提供者支持流式传输时生成缓冲区：

    ```kt
      void BindWaveform( clPtr<iWaveDataProvider> Wave )
      {
        FWaveDataProvider = Wave;
        if ( !Wave ) return;

        if ( Wave->IsStreaming() )
        {
          FBuffersCount = 2;
          alGenBuffers( FBuffersCount, &FBufferID[0] );
        }
        else
        {
          FBuffersCount = 1;
          alGenBuffers( FBuffersCount, &FBufferID[0] );
          alBufferData( FBufferID[0],
            Wave->GetALFormat(),
            Wave->GetWaveData(),
            (int)Wave->GetWaveDataSize(),
            Wave->FSamplesPerSec );
          alSourcei( FSourceID, AL_BUFFER, FBufferID[0] );
        }
      }
    ```

1.  `Play()`方法调用`alSourcePlay()`函数，并在流式传输模式下将缓冲区添加到队列中：

    ```kt
      void Play()
      {
        if ( IsPlaying() ) { return; }
        if ( !FWaveDataProvider ) { return; }

        int State;
        alGetSourcei( FSourceID, AL_SOURCE_STATE, &State );

        if (  State != AL_PAUSED &&
          FWaveDataProvider->IsStreaming() )
        {
          UnqueueAll();
    ```

1.  将两个音频缓冲区填充好并将它们提交给 OpenAL API：

    ```kt
          StreamBuffer( FBufferID[0], BUFFER_SIZE );
          StreamBuffer( FBufferID[1], BUFFER_SIZE );
          alSourceQueueBuffers(FSourceID, 2, &FBufferID[0]);
        }
        alSourcePlay( FSourceID );
      }
    ```

1.  既然我们使用了不止一个缓冲区，我们将在`UnqueueAll()`方法中将`FBufferID`更改为`FBufferID[0]`：

    ```kt
      void   UnqueueAll()
      {
        int Queued;
        alGetSourcei(FSourceID, AL_BUFFERS_QUEUED, &Queued);
        if ( Queued > 0 )
          alSourceUnqueueBuffers(FSourceID,
            Queued, &FBufferID[0]);
      }
    ```

1.  最后，由于流式传输是一个持续的过程，而不是一次性的操作，我们提供了`Update()`方法，它从`iWaveDataProvider`获取适当量的数据：

    ```kt
      void Update( float DeltaSeconds )
      {
        if ( !FWaveDataProvider ) { return; }
        if ( !IsPlaying() ) { return; }

        if ( FWaveDataProvider->IsStreaming() )
        {
          int Processed;
          alGetSourcei( FSourceID,
          AL_BUFFERS_PROCESSED, &Processed );

          while ( Processed-- )
          {
            unsigned int BufID;
            alSourceUnqueueBuffers(FSourceID,1,&BufID);
            StreamBuffer( BufID, BUFFER_SIZE );
            alSourceQueueBuffers(FSourceID, 1, &BufID);
          }
        }
      }
    ```

1.  在`Update()`方法中，我们使用了`StreamBuffer()`成员函数，它负责用提供者解码或生成的数据填充缓冲区：

    ```kt
      int StreamBuffer( unsigned int BufferID, int Size )
      {
        int ActualSize = 
          FWaveDataProvider->StreamWaveData(Size);

        ubyte* Data = FWaveDataProvider->GetWaveData();
        int Sz = (int)FWaveDataProvider->GetWaveDataSize();

        alBufferData( BufferID,
          FWaveDataProvider->GetALFormat(),
          Data, Sz,
          FWaveDataProvider->FSamplesPerSec );

        return ActualSize;
      }
    ```

1.  `BUFFER_SIZE`常数被设置为足够大，以容纳几秒钟的流式数据：

    ```kt
    const int BUFFER_SIZE = 352800;
    ```

    ### 注意

    值`352800`的推导如下：

    *2 通道 × 44,100 每秒采样数 × 每个样本 2 字节 × 2 秒 = 352,800 字节*。

## 工作原理…

本食谱中的代码没有实现`StreamWaveData()`方法。为了从扬声器中听到声音，我们编写了`ToneGenerator`类，它生成纯正弦波作为输出数据。这个类是从`StreamingWaveDataProvider`派生而来的：

```kt
class ToneGenerator : public StreamingWaveDataProvider
{
```

首先声明信号参数和内部样本计数器：

```kt
  int   FSignalFreq;
  float FFrequency;
  float FAmplitude;
private:
  int LastOffset;
```

构造函数设置声音数据参数并预先分配缓冲区空间：

```kt
public:
  ToneGenerator()
  {
    FBufferUsed = 100000;
    FBuffer.resize( 100000 );

    FChannels = 2;
    FSamplesPerSec = 4100;
    FBitsPerSample = 16;

    FAmplitude = 350.0f;
    FFrequency = 440.0f;
  }
  virtual ~ToneGenerator() {}
```

这个类的主例程计算正弦函数，跟踪当前样本索引，以使声音缓冲队列包含所有值：

```kt
  virtual int StreamWaveData( int Size )
  {
    if ( Size > static_cast<int>( FBuffer.size() ) )
    {
      FBuffer.resize( Size );
      LastOffset = 0;
    }

    for ( int i = 0 ; i < Size / 4 ; i++ )
    {
```

正弦函数的参数`t`是从局部索引`i`和名为`LastOffset`的相位值计算得出的：

```kt
      float t = ( 2.0f * 3.141592654f *
        FFrequency * ( i + LastOffset ) ) / 
         (float) FSamplesPerSec;
        float val = FAmplitude * std::sin( t );
```

以下几行代码将单个浮点数值转换成有符号字。这种转换是必要的，因为数字音频硬件只能处理整数数据：

```kt
      short V = static_cast<short>( val );
      FBuffer[i * 4 + 0] = V & 0xFF;
      FBuffer[i * 4 + 1] = V >> 8;
      FBuffer[i * 4 + 2] = V & 0xFF;
      FBuffer[i * 4 + 3] = V >> 8;
    }
```

接下来，我们在保持生成的样本计数器在`0…FSignalFreq-1`范围内时递增它：

```kt
    LastOffset += Size / 2;
    LastOffset %= FSamplesPerSec;
```

最后，返回生成的字节数：

```kt
    FBufferUsed = Size;
    return FBufferUsed;
  }
};
```

现在，我们可以使用`AudioSource`类来流式传输声音。一旦创建了音频源，我们就附加一个新的流式提供者，它生成 440 Hz 的正弦波形：

```kt
class SoundThread: public iThread
{
  virtual void Run()
  {
    while ( !g_Audio.Finitialized ) {}

    clPtr<AudioSource> Src = new AudioSource();
    Src->BindWaveform( new ToneGenerator() );
    Src->Play();

    FPendingExit = false;
    double Seconds = Env_GetSeconds();
```

在无限循环中，我们不断更新源，强制它生成声音数据：

```kt
    While ( !IsPendingExit() )
    {
      float DeltaSeconds =
         (float)( Env_GetSeconds() - Seconds );
      Src->Update( DeltaSeconds );
      Seconds = Env_GetSeconds();
    }
  }
}
```

## 还有更多…

容易注意到在`ToneGenerator::StreamWaveData()`成员函数中，我们可以使用任何公式，不仅仅是正弦函数。我们鼓励读者进行实验，创建某种软件合成器。

# 解码 Ogg Vorbis 文件

Ogg Vorbis 是一种广泛使用的、免费的、开放的、无专利的音频压缩格式。它可以与其他用于存储和播放数字音乐的格式相媲美，如 MP3、VQF 和 AAC。

## 准备就绪

读者应该熟悉前一个食谱中的声音流传输技术。关于`.ogg`容器文件格式和 Vorbis 音频压缩算法的详细信息可以在[`xiph.org`](http://xiph.org)找到。

## 如何操作…

1.  我们向`iWaveDataProvider`接口添加了`IsEOF()`方法。这用于通知`AudioSource`声音何时结束：

    ```kt
      virtual bool    IsEOF() const { return true; }
    ```

1.  我们添加的另一个方法是`Seek()`，它倒带音频流：

    ```kt
      virtual void    Seek( float Time ) {}
    ```

1.  在`DecodingProvider`类中，我们实现了`StreamWaveData()`成员函数，它使用`ReadFromFile()`方法从源内存块中读取解码的音频数据：

    ```kt
    class DecodingProvider: public StreamingWaveDataProvider
    {
      clPtr<Blob> FRawData;
    public:
      bool FEof;
      virtual bool IsEOF() const { return FEof; }
    ```

1.  `FLoop`标志告诉解码器，如果遇到流末尾，则倒回并从开始处重新播放：

    ```kt
      bool FLoop;
    public:
      DecodingProvider( const clPtr<Blob>& blob )
      {
        FRawData = blob;
        FEof = false;
      }
    ```

1.  主要的流处理程序尝试从源内存块中读取更多数据：

    ```kt
      virtual int StreamWaveData( int Size )
      {
    ```

1.  我们用零填充缓冲区的未使用部分以避免噪音：

    ```kt
        int OldSize = (int)FBuffer.size();
        if ( Size > OldSize )
        {
          FBuffer.resize( Size );
          for ( int i = 0 ; i < OldSize - Size ; i++ )
            FBuffer[OldSize + i] = 0;
        }
    ```

1.  在文件末尾，我们将解码数据的大小返回为零：

    ```kt
        if ( FEof ) { return 0; }
    ```

1.  接下来，我们尝试从源读取，直到收集到`Size`个字节：

    ```kt
        int BytesRead = 0;
        while ( BytesRead < Size )
        {
          int Ret = ReadFromFile(Size);
    ```

1.  如果我们有数据，增加计数器：

    ```kt
          if ( Ret > 0 )
          {
            BytesRead += Ret;
          }
    ```

1.  如果字节数为零，我们已经到达文件的末尾：

    ```kt
          else if (Ret == 0)
            {
            FEof = true;
    ```

1.  `FLoop`标志告诉我们需要将流倒回到开始处：

    ```kt
            if ( FLoop )
            {
              Seek(0);
              FEof = false;
              continue;
            }
            break;
          } else
    ```

1.  否则，我们在流中有一个错误：

    ```kt
          {
            Seek( 0 );
            FEof = true;
            break;
          }
        }
    ```

1.  当前缓冲的字节数现在是文件中读取的字节数：

    ```kt
        return ( FBufferUsed = BytesRead );
      }
    ```

1.  `ReadFromFile()`函数在这里是纯虚的，实现都在派生类中：

    ```kt
    protected:
      virtual int ReadFromFile(int Size) = 0;
    };
    ```

1.  在第二章《移植通用库》中，我们编译了 Ogg 和 Vorbis 静态库。我们现在在`OggProvider`类中使用它们，该类实现了实际音频数据的解码：

    ```kt
    class OggProvider: public DecodingProvider
    {
    ```

1.  解码器的状态存在于三个变量中：

    ```kt
      OggVorbis_File         FVorbisFile;
      ogg_int64_t            FOGGRawPosition;
      int                    FOGGCurrentSection;
    ```

1.  构造函数初始化 Ogg 和 Vorbis 库。`Callbacks`结构包含指向函数的指针，这允许 OGG 库使用我们的虚拟文件系统流从我们的内存块中读取数据：

    ```kt
    public:
      OggProvider( const clPtr<Blob>& Blob ): DecodingProvider(Blob)
      {
        FOGGRawPosition = 0;
    ```

1.  填充`Callbacks`结构并初始化文件阅读器：

    ```kt
        ov_callbacks Callbacks;
        Callbacks.read_func  = OGG_ReadFunc;
        Callbacks.seek_func  = OGG_SeekFunc;
        Callbacks.close_func = OGG_CloseFunc;
        Callbacks.tell_func  = OGG_TellFunc;
        OGG_ov_open_callbacks( this, &FVorbisFile,
        NULL, -1, Callbacks );
    ```

1.  声明`vorbis_info`结构以读取音频流的持续时间。存储关于流的信息：

    ```kt
        vorbis_info* VorbisInfo;
        VorbisInfo     = OGG_ov_info ( &FVorbisFile, -1 );
        FChannels      = VorbisInfo->channels;
        FSamplesPerSec = VorbisInfo->rate;
    ```

1.  `FBitsPerSample`结构被设置为 16 位，然后我们告诉解码器以 16 位信号输出音频数据：

    ```kt
        FBitsPerSample = 16;
      }
    ```

1.  在析构函数中，`FVorbisFile`被清除：

    ```kt
      virtual ~OggProvider() { OGG_ov_clear( &FVorbisFile ); }
    ```

1.  `ReadFromFile()`函数使用 OGG 库进行流解码：

    ```kt
      virtual int ReadFromFile(int Size, int BytesRead)
      {
        return (int)OGG_ov_read( &FVorbisFile,
          &FBuffer[0] + BytesRead,
          Size - BytesRead,
    ```

1.  在这里，我们假设我们正在小端 CPU 上运行，例如 Intel Atom、Intel Core，或其他通常在移动 Android 设备中遇到的 ARM 处理器（[`en.wikipedia.org/wiki/Endianness`](http://en.wikipedia.org/wiki/Endianness)）。如果不是这种情况，例如处理器是 PowerPC 或 MIPS 在大端模式下，你应该向`OGG_ov_read()`函数提供一个`1`作为参数：

    ```kt
          0, // 0 for LITTLE_ENDIAN, 1 for BIG_ENDIAN
          FBitsPerSample >> 3,
          1,
          &FOGGCurrentSection );
      }
    ```

1.  `Seek()`成员函数将流倒回到指定的时间：

    ```kt
      virtual void Seek( float Time )
      {
        FEof = false;
        OGG_ov_time_seek( &FVorbisFile, Time );
      }
    ```

1.  在类的定义末尾，包含了`OGG_Callbacks.h`文件，其中实现了静态回调函数：

    ```kt
    private:
      #include "OGG_Callbacks.h"
    };
    ```

1.  `OGG_Callbacks.h`文件中的函数实现了一个类似`FILE*`的接口，OGG 库使用它来读取我们的内存块。我们在所有这些函数中将`OggProvider`的实例作为`void* DataSource`参数传递。

1.  `OGG_ReadFunc()`函数读取指定数量的字节并检查数据的末尾：

    ```kt
    size_t OGG_ReadFunc( void* Ptr, size_t Size, size_t NMemB,
      void* DataSource )
      {
        OggProvider* OGG = (OggProvider*)DataSource;

        size_t DataSize = OGG->FRawData->GetSize();

        ogg_int64_t BytesRead = DataSize - OGG- >FOGGRawPosition;
        ogg_int64_t BytesSize = Size * NMemB;

        if ( BytesSize < BytesRead ) { BytesRead = BytesSize; }

        memcpy( Ptr,
          (ubyte*)OGG->FRawData->GetDataConst() +
            OGG->FOGGRawPosition, (size_t)BytesRead );

        OGG->FOGGRawPosition += BytesRead;
        return (size_t)BytesRead;
      }
    ```

1.  `OGG_SeekFunc()`函数将当前读取位置设置为`Offset`的值：

    ```kt
      int OGG_SeekFunc( void* DataSource, ogg_int64_t Offset,
      int Whence )
      {
        OggProvider* OGG = (OggProvider*)DataSource;
        size_t DataSize = OGG->FRawData->GetSize();
        if ( Whence == SEEK_SET )
        {
          OGG->FOGGRawPosition = Offset;
        }
        else if ( Whence == SEEK_CUR )
        {
          OGG->FOGGRawPosition += Offset;
        }
        else if ( Whence == SEEK_END )
        {
          OGG->FOGGRawPosition = DataSize + Offset;
        }
    ```

1.  防止位置超过流结尾：

    ```kt
        if ( OGG->FOGGRawPosition > (ogg_int64_t)DataSize )
        {
          OGG->FOGGRawPosition = (ogg_int64_t)DataSize;
        }
        return static_cast<int>( OGG->FOGGRawPosition );
      }
    ```

1.  由于我们使用内存块作为数据源，`OGG_CloseFunc()`函数立即返回零，因为我们不需要关闭任何句柄：

    ```kt
      int OGG_CloseFunc( void* DataSource ) { return 0; }
    ```

1.  `OGG_TellFunc()`函数返回当前的读取位置：

    ```kt
      long OGG_TellFunc( void* DataSource )
      {
        return (int)
          (((OggProvider*)DataSource)->FOGGRawPosition);
      }
    ```

## 工作原理…

我们像之前的食谱一样初始化 OpenAL，并将`OggProvider`绑定到`AudioSource`实例的数据源：

```kt
  clPtr<AudioSource> Src = new AudioSource();
  clPtr<Data> = LoadFileAsBlob( "test.ogg" );
  Src->BindWaveform( new OggProvider(Data) );
  Src->Play();
  FPendingExit = false;
  double Seconds = Env_GetSeconds();
```

在循环中更新音频源，就像我们对`ToneGenerator`所做的那样：

```kt
  While ( !IsPendingExit() )
  {
    float DeltaSeconds =
       (float)(Env_GetSeconds() - Seconds );
    Src->Update(DeltaSeconds);
    Seconds = Env_GetSeconds();
  }
```

`LoadFileAsBlob()`函数与我们用来加载`.wav`文件的函数相同。

# 使用 ModPlug 解码跟踪器音乐

与桌面计算机相比，移动设备在资源上总是受限的。这些限制既包括计算能力，也包括可用的存储空间。即使是在适中的比特率下，高质量的 MPEG-1 Layer 3 或 Ogg Vorbis 音频文件也会占用大量空间。例如，在一个 20 Mb 的游戏中，两个各占 5 Mb 大小的音轨是不可接受的。然而，质量和压缩之间有一个很好的折中方案。一种起源于八十年代的技术，称为跟踪器音乐——有时也被称为芯片音乐或 8 位音乐（[`en.wikipedia.org/wiki/Music_tracker`](http://en.wikipedia.org/wiki/Music_tracker)）。跟踪器音乐格式不使用脉冲编码调制来存储整个音轨。相反，它们使用`音符`和效果，这些音符和效果被应用到`样本`并在多个通道中播放。`样本`是乐器的小型 PCM 编码声音。`音符`对应于样本的播放速度。我们使用**libmodplug**库来解码最流行的跟踪器音乐文件格式，如`.it`、`.xm`和`.mod`。

## 准备就绪

在[`modplug-xmms.sourceforge.net`](http://modplug-xmms.sourceforge.net)查看 libmodplug 的最新版本。

## 如何操作...

1.  ModPlug 库允许我们实现另一个从`DecodingProvider`派生的类，称为`ModPlugProvider`。该库支持直接解码内存块，因此我们不需要实现任何 I/O 回调：

    ```kt
    class ModPlugProvider: public DecodingProvider
    {
    ```

1.  作为状态，这个类包含了`ModPlugFile`结构：

    ```kt
    private:
      ModPlugFile* FModFile;
    ```

1.  唯一的构造函数初始化了`ModPlugFile`字段：

    ```kt
    public:
      explicit ModPlugProvider( const clPtr<Blob>& Blob )
      : DecodingProvider(Blob)
      {
        FChannels = 2;
        FSamplesPerSec = 44100;
        FBitsPerSample = 16;

        FModFile = ModPlug_Load_P(
          ( const void* )FRawData->GetDataConst(),
          ( int )FRawData->GetSize() );
      }
    ```

1.  析构函数卸载文件：

    ```kt
      virtual ~ModPlugProvider() { ModPlug_Unload_P( FModFile ); }
    ```

1.  `ReadFromFile()`方法调用 ModPlug 的读取函数：

    ```kt
      virtual int ReadFromFile(int Size, int BytesRead)
      {
        return ModPlug_Read_P( FModFile,
          &FBuffer[0] + BytesRead,
          Size - BytesRead );
      }
    ```

1.  要重置源流，我们使用`ModPlug_Seek()`成员函数：

    ```kt
      virtual void Seek( float Time )
      {
        FEof = false;
        ModPlug_Seek_P( FModFile, ( int )( Time * 1000.0f ) );
      }
    };
    ```

## 工作原理...

没有专用的样本用于模块文件解码。为了更好地理解，我们建议修改`3_AL_PlayingOGG`源代码。唯一需要的修改是将`OggProvider`替换为`ModPlugProvider`。在测试中，你可以在`3_AL_PlayingOGG`文件夹中找到`test.it`文件。

## 另请参阅

+   *解码 Ogg Vorbis 文件*


# 第六章：统一 OpenGL ES 3 和 OpenGL 3

在本章中，我们将涵盖：

+   统一 OpenGL 3 核心配置文件和 OpenGL ES 2

+   在 Windows 上初始化 OpenGL 3 核心配置文件

+   在 Android 上初始化 OpenGL ES 2

+   统一 GLSL 3 和 GLSL ES 2 着色器

+   操作几何图形

+   统一顶点数组

+   为纹理创建一个包装器

+   创建一个用于即时渲染的画布

# 引言

毫无疑问，任何游戏都需要渲染一些图形。在本章中，我们将学习如何为你的游戏创建一个可移植的图形渲染子系统。章节标题为《统一 OpenGL ES 3 和 OpenGL 3》；然而，在本书中我们处理的是可移植开发，因此我们从 OpenGL 3 桌面 API 开始我们的教程。这有两个目的。首先，OpenGL 3 几乎是 OpenGL ES 3 的超集。这将允许我们轻松地在两个 OpenGL API 版本之间移植应用程序。其次，我们可以创建一个简单但非常有效的包装器，来抽象游戏代码中的两个 API，这样我们就能在桌面 PC 上开发我们的游戏。

### 注意

OpenGL ES 3 的支持在 Android 4.3 和 Android NDK r9 中引入。然而，本书中的所有示例都向下兼容此移动 API 的前一个版本，即 OpenGL ES 2。

OpenGL 本身是一个庞大的主题，值得专门用一本书来讲述。我们建议从《OpenGL 编程指南》，*Pearson 出版物*（红书）开始学习。

# 统一 OpenGL 3 核心配置文件和 OpenGL ES 2

让我们在 OpenGL 3 和 OpenGL ES 2 之上实现一个薄的抽象层，使我们的高级代码不知道应用程序运行的具体 GL 版本。这意味着我们的游戏代码可以完全不知道它是在移动版还是桌面版的 OpenGL 上运行。请看以下图表：

![统一 OpenGL 3 核心配置文件和 OpenGL ES 2](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_06_1.jpg)

我们将在本章中实现的部分位于**高级 API** 矩形内。

## 准备就绪

在第四章，*组织虚拟文件系统*中，我们创建了一个示例 `3_AsyncTexture`，我们学习了如何在 Android 上使用 Java 初始化 OpenGL ES 2。现在我们使用该示例中的 `GLView.java` 在 Android 上初始化一个渲染上下文。不涉及来自 Android NDK 的 EGL，因此我们的示例将在 Android 2.1 及更高版本上运行。

## 如何操作…

1.  在上一个教程中，我们提到了 `sLGLAPI` 结构。它包含在启动时动态加载的 OpenGL 函数的指针。声明可以在 `LGLAPI.h` 中找到，它从以下代码开始：

    ```kt
    struct sLGLAPI
    {
      sLGLAPI() { memset( this, 0, sizeof( *this ) ); };
    …Win32 defines skipped here…
      PFNGLACTIVETEXTUREPROC       glActiveTexture;
      PFNGLATTACHSHADERPROC        glAttachShader;
      PFNGLBINDATTRIBLOCATIONPROC  glBindAttribLocation;
    …
    ```

1.  定义一个变量来保存指向此结构的指针：

    ```kt
    sLGLAPI* LGL3;
    ```

1.  这意味着我们必须通过包含在 `LGL3` 中的指针调用所有 OpenGL 函数。例如，以下是来自 `2_OpenGLES2` 示例的 `OnDrawFrame()` 的代码：

    ```kt
    void OnDrawFrame()
    {
      LGL3->glClearColor( 1.0, 0.0, 0.0, 0.0 );
      LGL3->glClear( GL_COLOR_BUFFER_BIT );
    }
    ```

    比简单的`glClear(GL_COLOR_BUFFER_BIT)`调用复杂一点，那么为什么我们需要它呢？根据你的应用程序在不同平台上链接到 OpenGL 的方式，`glClear`类的实体可以以两种方式表示。如果你的应用程序是动态链接到 OpenGL 的，那么像`glClear`这样的全局符号由持有从`.DLL/.so`库中检索的函数指针的全局变量表示。你的应用程序也可能静态链接到某些 OpenGL 包装库，正如在 Android 上使用`-lGLESv2`和`-lGLESv3`开关在`LOCAL_LDLIBS`中所做的那样。在这种情况下，`glClear()`将是一个函数，而不是一个变量，你不能更改它包含的代码。此外，如果我们查看某些 OpenGL 3 函数，例如`glClearDepth(double Depth)`，却发现 OpenGL ES 2 没有直接等效的函数，事情就会变得更加复杂。这就是为什么我们需要一个可以随意更改的 OpenGL 函数指针集合。

1.  在 Android 上，我们定义了一个 thunk 函数：

    ```kt
    void Emulate_glClearDepth( double Depth )
    {
      glClearDepthf( static_cast<float>( Depth ) );
    }
    ```

1.  这个函数模拟了 OpenGL 3 的`glClearDepth()`调用，使用了 OpenGL ES 3 的`glClearDepthf()`调用。现在事情又变得简单了。有些 GL3 函数不能在 GLES3 中轻易模拟。现在我们可以轻松地为它们实现空的存根，例如：

    ```kt
    void Emulate_glPolygonMode( GLenum, GLenum )
    {
      // not supported
    }
    ```

在此情况下，未实现的功能将禁用一些渲染能力；但应用程序将正常运行，在 GLES2 上优雅降级。一些更复杂的内容，例如使用`glBindFragDataLocation()`的多重渲染目标，仍然需要我们为 OpenGL 3 和 OpenGL ES 2 选择不同的着色器程序和代码路径。然而，现在这是可行的。

## 工作原理…

`sLGLAPI`绑定代码在`GetAPI()`函数中实现。之前描述的 Windows 版本是简单的`.DLL`加载代码。Android 版本甚至更简单。由于我们的应用程序是静态链接到 OpenGL ES 2 库的，我们只需将函数指针分配给`sLGLAPI`的字段，除了在 OpenGL ES 2 中不存在的调用：

```kt
void GetAPI( sLGLAPI* API ) const
{
  API->glActiveTexture = &glActiveTexture;
  API->glAttachShader = &glAttachShader;
  API->glBindAttribLocation = &glBindAttribLocation;
…
```

相反，我们使用之前描述的存根：

```kt
  API->glClearDepth = &Emulate_glClearDepth;
  API->glBindFragDataLocation = &Emulate_glBindFragDataLocation;
…
```

现在 OpenGL 的使用完全是透明的，我们的应用程序完全不知道实际使用的是哪种 OpenGL 版本。看看`OpenGL3.cpp`文件：

```kt
#include <stdlib.h>
#include "LGL.h"
sLGLAPI* LGL3 = NULL;
void OnDrawFrame()
{
  LGL3->glClearColor( 1.0, 0.0, 0.0, 0.0 );
  LGL3->glClear( GL_COLOR_BUFFER_BIT );
}
```

这段代码在 Windows 和 Android 上运行完全相同。

## 还有更多…

使用以下命令可以构建`2_OpenGLES2`示例的 Android 版本：

```kt
>ndk-build
>ant copy-common-media debug

```

运行应用程序将整个屏幕涂成红色，并将表面大小输出到系统日志中：

```kt
W/GLView  ( 3581): creating OpenGL ES 2.0 context
I/App13   ( 3581): SurfaceSize: 1196 x 720
```

在 OpenGL 3 Core Profile、OpenGL ES 2 和 OpenGL ES 3 之间还存在其他无法通过模仿所有 API 函数调用来抽象的差异。这包括 GLSL 着色器的不同语法，以及在 OpenGL 3.2 Core Profile 中必须使用的顶点数组对象（VAO），这在 OpenGL ES 2 中是不存在的。

## 另请参阅

+   统一 GLSL 3 和 GLSL ES 2 着色器

+   操作几何图形

+   统一顶点数组

+   创建纹理的包装器

# 在 Windows 上初始化 OpenGL 3 核心配置文件

OpenGL 3.0 引入了功能弃用的概念。某些功能可能被标记为弃用，并在后续版本中从规范中移除。例如，通过 `glBegin` `()/glEnd` `()` 的立即模式渲染在 OpenGL 标准版本 3.0 中被标记为弃用，并在版本 3.1 中移除。然而，许多 OpenGL 实现保留了弃用的功能。例如，它们希望为使用现代 OpenGL 版本的用户提供一种访问旧 API 功能的方法。

从 OpenGL 版本 3.2 开始，引入了一种新机制，允许用户创建特定版本的渲染上下文。每个版本都允许**向后兼容**或**核心配置文件**上下文。向后兼容的上下文允许使用所有标记为弃用的功能。核心配置文件上下文移除了弃用的功能，使 API 更干净。此外，OpenGL 3 核心配置文件比之前的 OpenGL 版本更接近移动 OpenGL ES 2。由于本书的目标是提供一种在桌面上开发移动应用程序的方法，这种功能集的相似性将非常有用。让我们找出如何在 Windows 上手动创建核心配置文件上下文。

### 注意

对于使用 Unix 或 Mac 桌面计算机的读者，我们建议使用 GLFW 库来创建 OpenGL 上下文，该库可在[`www.glfw.org`](http://www.glfw.org)获取。

## 准备就绪

有关核心和兼容性上下文的更多信息可以在官方 OpenGL 页面找到，链接为[`www.opengl.org/wiki/Core_And_Compatibility_in_Contexts`](http://www.opengl.org/wiki/Core_And_Compatibility_in_Contexts)。

## 如何操作…

有一个名为 `WGL_ARB_create_context` 的 OpenGL 扩展，可以在 Windows 上创建特定版本的 OpenGL 上下文，相关信息可在[`www.opengl.org/registry/specs/ARB/wgl_create_context.txt`](http://www.opengl.org/registry/specs/ARB/wgl_create_context.txt)找到。

技巧在于，我们只能从现有的有效 OpenGL 上下文中获取到 `wglCreateContextAttribsARB()` 函数的指针，该函数可以创建核心配置文件上下文。这意味着我们必须初始化 OpenGL 两次。首先，我们使用 `glCreateContext()` 创建一个临时的兼容性上下文，并获取到 `wglCreateContextAttribsARB()` 扩展函数的指针。然后，我们继续使用扩展函数创建指定版本和所需标志的 OpenGL 上下文。以下是我们用于创建 OpenGL 渲染上下文的代码：

### 注意

`sLGLAPI` 结构包含我们使用的所有 OpenGL 函数的指针。阅读之前的菜谱 *统一 OpenGL 3 核心配置文件和 OpenGL ES 2* 以了解实现细节。

```kt
HGLRC CreateContext( sLGLAPI* LGL3, HDC DeviceContext,int VersionMajor, int VersionMinor )
{
  HGLRC RenderContext = 0;
```

第一次调用此函数时，它会进入`else`块并创建一个向后兼容的 OpenGL 上下文。当你获取到有效的`wglCreateContextAttribsARB()`函数指针时，将其保存在`sLGLAPI`结构中，并再次调用`CreateContext()`。这次第一个`if`块将接管控制：

```kt
  if ( LGL3->wglCreateContextAttribsARB )
  {
    const int Attribs[] =
    {
      WGL_CONTEXT_MAJOR_VERSION_ARB, VersionMajor,
      WGL_CONTEXT_MINOR_VERSION_ARB, VersionMinor,
      WGL_CONTEXT_LAYER_PLANE_ARB, 0,
      WGL_CONTEXT_FLAGS_ARB,
      WGL_CONTEXT_FORWARD_COMPATIBLE_BIT_ARB,
      WGL_CONTEXT_PROFILE_MASK_ARB,
      WGL_CONTEXT_CORE_PROFILE_BIT_ARB,
      0 // zero marks the end of values
    };
    RenderContext = LGL3->wglCreateContextAttribsARB(DeviceContext, 0, Attribs );
  }
  else
  {
```

1.  `lglCreateContext()`调用只是针对特定操作系统 API 调用的封装，在本例中是`wglCreateContext()`：

    ```kt
        RenderContext = LGL3->lglCreateContext(DeviceContext );
      }
      return RenderContext;
    }
    ```

1.  这个函数被包装在`CreateContextFull()`函数中，它选择适当的像素格式并使上下文成为当前：

    ```kt
    HGLRC CreateContextFull( sLGLAPI* LGL3, HDC DeviceContext,int BitsPerPixel, int ZBufferBits, int StencilBits,int Multisample, int VersionMajor, int VersionMinor )
    {
      bool FormatSet = ChooseAndSetPixelFormat( LGL3,DeviceContext,BitsPerPixel, ZBufferBits, StencilBits, Multisample );
      if ( !FormatSet ) return 0;
      HGLRC RenderContext = CreateContext( LGL3,DeviceContext, VersionMajor, VersionMinor );
      if ( !RenderContext ) return 0;
      if ( !MakeCurrent( LGL3, DeviceContext, RenderContext ) )
      { return 0; }
      Reload( LGL3 );
      return RenderContext;
    }
    ```

    它返回创建的 OpenGL 渲染上下文，在 Windows 上是`HGLRC`，并更新`LGL3`结构中的指针以对应创建的上下文。

    ### 注意

    之前描述的函数有许多副作用，一些函数式程序员认为它不一致。另一种方法是返回一个新的`HGLRC`以及新的`LGL3`（或者作为新`LGL3`的一部分），这样你可以在稍后自行决定使其成为当前上下文，并且仍然可以访问旧的上下文。我们将这个想法留给读者作为一个练习。

    之前提到的`Reload()`函数重新加载了`sLGLAPI`结构中的 OpenGL 函数指针。这种间接调用很重要，因为我们需要模拟 OpenGL 3 函数在 OpenGL ES 2 上的行为。

    像素格式选择还使用了另一个 OpenGL 扩展：`WGL_ARB_pixel_format`，可在[`www.opengl.org/registry/specs/ARB/wgl_pixel_format.txt`](http://www.opengl.org/registry/specs/ARB/wgl_pixel_format.txt)找到。

1.  这意味着我们必须选择并设置像素格式两次。代码如下：

    ```kt
    bool ChooseAndSetPixelFormat( sLGLAPI* LGL3, HDCDeviceContext,int BitsPerPixel, int ZBufferBits, int StencilBits,int Multisample )
    {
      PIXELFORMATDESCRIPTOR PFD;
      memset( &PFD, 0, sizeof( PFD ) );
      PFD.nSize        = sizeof( PIXELFORMATDESCRIPTOR );
      PFD.nVersion     = 1;
      PFD.dwFlags = PFD_DRAW_TO_WINDOW |
                    PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
      PFD.iPixelType = PFD_TYPE_RGBA;
      PFD.cColorBits = static_cast<BYTE>(BitsPerPixel & 0xFF);
      PFD.cDepthBits = static_cast<BYTE>(ZBufferBits & 0xFF);
      PFD.cStencilBits = static_cast<BYTE>(StencilBits & 0xFF);
      PFD.iLayerType = PFD_MAIN_PLANE;
      GLint PixelFormat = 0;
    ```

1.  如果有效的指针可用，请尝试使用该扩展：

    ```kt
      if ( LGL3->wglChoosePixelFormatARB )
      {
        const int Attribs[] =
        {
          WGL_DRAW_TO_WINDOW_ARB, GL_TRUE,WGL_SUPPORT_OPENGL_ARB, GL_TRUE,WGL_ACCELERATION_ARB, WGL_FULL_ACCELERATION_ARB,WGL_DOUBLE_BUFFER_ARB , GL_TRUE,WGL_PIXEL_TYPE_ARB    , WGL_TYPE_RGBA_ARB,WGL_COLOR_BITS_ARB    , BitsPerPixel,WGL_DEPTH_BITS_ARB    , ZBufferBits,WGL_STENCIL_BITS_ARB  , StencilBits,WGL_SAMPLE_BUFFERS_ARB, GL_TRUE,WGL_SAMPLES_ARB       , Multisample,0 // zero marks the end of values
        };
        GLuint Count = 0;
        LGL3->wglChoosePixelFormatARB( DeviceContext,Attribs, NULL, 1, &PixelFormat, &Count );
        if ( !PixelFormat )
        {
          PixelFormat = ::ChoosePixelFormat(
            DeviceContext, &PFD );
        }
        return ::SetPixelFormat( DeviceContext,PixelFormat, NULL );
      }
    ```

1.  或者，退回到 WinAPI 提供的像素格式选择函数：

    ```kt
      if ( !PixelFormat )
      {
        PixelFormat = ::ChoosePixelFormat(DeviceContext, &PFD);
      }
      return ::SetPixelFormat( DeviceContext,
        PixelFormat, &PFD );
    }
    ```

## 它的工作原理是…

`Reload()`函数加载`opengl32.dll`并获取某些 WGL 函数的指针（[`en.wikipedia.org/wiki/WGL_(API)`](http://en.wikipedia.org/wiki/WGL_(API))）：

```kt
void LGL::clGLExtRetriever::Reload( sLGLAPI* LGL3 )
{
  if ( !FLibHandle ) FLibHandle =
    (void*)::LoadLibrary( "opengl32.dll" );
  LGL3->lglGetProcAddress = ( PFNwglGetProcAddress )
    ::GetProcAddress( (HMODULE)FLibHandle, "wglGetProcAddress" );
  LGL3->lglCreateContext = ( PFNwglCreateContext )
    ::GetProcAddress( (HMODULE)FLibHandle, "wglCreateContext" );
  LGL3->lglGetCurrentContext = ( PFNwglGetCurrentContext )
    ::GetProcAddress( (HMODULE)FLibHandle,"wglGetCurrentContext");
  LGL3->lglMakeCurrent = ( PFNwglMakeCurrent )
    ::GetProcAddress( (HMODULE)FLibHandle, "wglMakeCurrent" );
  LGL3->lglDeleteContext = ( PFNwglDeleteContext )
    ::GetProcAddress( (HMODULE)FLibHandle, "wglDeleteContext" );
  GetAPI( LGL3 );
}
```

`GetAPI()`函数要大得多，但仍然很简单。以下是一些代码行，以给你一个大概的想法：

```kt
void LGL::clGLExtRetriever::GetAPI( sLGLAPI* API ) const
{
  API->glActiveTexture = ( PFNGLACTIVETEXTUREPROC )GetGLProc( API, "glActiveTexture" );
  API->glAttachShader = ( PFNGLATTACHSHADERPROC )GetGLProc( API, "glAttachShader" );
…
```

完整的源代码在`1_OpenGL3`文件夹中。你可以使用`make`来构建它：

```kt
>make all

```

本示例打开一个背景为红色的窗口，并打印出类似于以下内容的行：

```kt
Using glCreateContext()
Using wglCreateContextAttribsARB()
OpenGL version: 3.2.0
OpenGL renderer: GeForce GTX 560/PCIe/SSE2
OpenGL vendor: NVIDIA Corporation
```

OpenGL 上下文版本与`glCreateContextAttribsARB()`调用中指定的版本相匹配。

## 还有更多…

在 WinAPI 中不允许多次设置窗口的像素格式。因此，我们使用一个临时的不可见窗口来创建第一个渲染上下文并获取扩展。查看`1_OpenGL3`示例中的`OpenGL3.cpp`文件，了解进一步的实现细节。

## 另请参阅

+   *统一 OpenGL 3 核心配置文件和 OpenGL ES 3*

# 在 Android 上初始化 OpenGL ES 2。

与 Windows 相比，Android 上的 OpenGL 初始化非常直接。在 Android NDK 中创建 OpenGL 渲染上下文有两种方法：直接使用来自 NDK 的 EGL API（[`en.wikipedia.org/wiki/EGL_(API)`](http://en.wikipedia.org/wiki/EGL_(API)）），或者基于`android.opengl.GLSurfaceView`创建一个包装 Java 类。我们将选择第二种方法。

## 准备就绪

熟悉`GLSurfaceView`类的接口，请访问[`developer.android.com/reference/android/opengl/GLSurfaceView.html`](http://developer.android.com/reference/android/opengl/GLSurfaceView.html)。

## 如何操作…

1.  我们以下列方式扩展了`GLSurfaceView`类：

    ```kt
    public class GLView extends GLSurfaceView
    {
      …
    ```

1.  `init()`方法为帧缓冲区选择`RGB_888`像素格式：

    ```kt
      private void init( int depth, int stencil )
      {
        this.getHolder().setFormat( PixelFormat.RGB_888 );
        setEGLContextFactory( new ContextFactory() );
        setEGLConfigChooser(new ConfigChooser( 8, 8, 8, 0, depth, stencil ) );
        setRenderer( new Renderer() );
      }
    ```

1.  这个内部类执行 EGL 调用以创建 OpenGL 渲染上下文：

    ```kt
      private static class ContextFactory implementsGLSurfaceView.EGLContextFactory
      {
        private static int EGL_CONTEXT_CLIENT_VERSION = 0x3098;
        public EGLContext createContext( EGL10 egl,EGLDisplay display, EGLConfig eglConfig )
        {
          int[] attrib_list = { EGL_CONTEXT_CLIENT_VERSION 2,EGL10.EGL_NONE };
          EGLContext context = egl.eglCreateContext(display, eglConfig, EGL10.EGL_NO_CONTEXT,attrib_list );
          return context;
        }
        public void destroyContext( EGL10 egl,EGLDisplay display, EGLContext context )
        {
          egl.eglDestroyContext( display, context );
        }
      }
    ```

1.  `ConfigChooser`类处理像素格式。在本书中我们省略了所有错误检查；然而，在`2_OpenGLES2`示例的`GLView.java`文件中可以找到一个更健壮的实现：

    ```kt
      private static class ConfigChooser implementsGLSurfaceView.EGLConfigChooser
      {
        public ConfigChooser( int r, int g, int b, int a,int depth, int stencil )
    …
        private static int EGL_OPENGL_ES2_BIT = 4;
    ```

1.  我们像素格式选择器的默认值为：

    ```kt
        private static int[] s_configAttribs2 =
        {
          EGL10.EGL_RED_SIZE, 5,EGL10.EGL_GREEN_SIZE, 6,EGL10.EGL_BLUE_SIZE, 5,EGL10.EGL_ALPHA_SIZE, 0,EGL10.EGL_DEPTH_SIZE, 16,EGL10.EGL_STENCIL_SIZE, 0,EGL10.EGL_SAMPLE_BUFFERS, 0,EGL10.EGL_SAMPLES, 0,EGL10.EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,EGL10.EGL_NONE, EGL10.EGL_NONE
        };
        public EGLConfig chooseConfig( EGL10 egl,EGLDisplay display )
        {
          int[] num_config = new int[1];
          egl.eglChooseConfig( display, s_configAttribs2,null, 0, num_config );
          int numConfigs = num_config[0];
          …
    ```

1.  分配并读取最小匹配 EGL 配置的数组：

    ```kt
          EGLConfig[] configs = new EGLConfig[numConfigs];
          egl.eglChooseConfig( display, s_configAttribs2,configs, numConfigs, num_config );
    ```

1.  选择最佳匹配项：

    ```kt
          return chooseConfig( egl, display, configs );
        }

        public EGLConfig chooseConfig( EGL10 egl,EGLDisplay display, EGLConfig[] configs )
        {
          for ( EGLConfig config : configs )
          {
    ```

1.  选择具有指定深度缓冲区和模板缓冲区位的配置：

    ```kt
            int d = findConfigAttrib( egl, display,config, EGL10.EGL_DEPTH_SIZE,   0 );
            int s = findConfigAttrib( egl, display,config, EGL10.EGL_STENCIL_SIZE, 0 );
    ```

1.  我们至少需要`mDepthSize`和`mStencilSize`位来进行深度和模板处理：

    ```kt
            if ( d < mDepthSize || s < mStencilSize )
            {
              continue;
            }
    ```

1.  我们希望红/绿/蓝/透明位有一个完全匹配：

    ```kt
            int r = findConfigAttrib( egl, display,config, EGL10.EGL_RED_SIZE,   0 );
            int g = findConfigAttrib( egl, display,config, EGL10.EGL_GREEN_SIZE, 0 );
            int b = findConfigAttrib( egl, display,config, EGL10.EGL_BLUE_SIZE,  0 );
            int a = findConfigAttrib( egl, display,config, EGL10.EGL_ALPHA_SIZE, 0 );
            if ( r == mRedSize && g == mGreenSize &&b == mBlueSize && a == mAlphaSize )
            {
              return config;
            }
          }
          return null;
        }
    ```

1.  使用辅助方法查找匹配的配置：

    ```kt
        private int findConfigAttrib( EGL10 egl,EGLDisplay display, EGLConfig config,int attribute, int defaultValue )
        {
          if ( egl.eglGetConfigAttrib( display,config, attribute, mValue ) )
          {
            return mValue[0];
          }
          return defaultValue;
        }
    …
      }
    ```

1.  `Renderer`类将帧渲染回调委托给我们的 NDK 代码：

    ```kt
      private static class Rendererimplements GLSurfaceView.Renderer
      {
        public void onDrawFrame( GL10 gl )
        {
          App13Activity.DrawFrame();
        }
        public void onSurfaceChanged( GL10 gl,int width, int height )
        {
          App13Activity.SetSurfaceSize( width, height );
        }
        public void onSurfaceCreated( GL10 gl,EGLConfig config )
        {
         App13Activity.SetSurface(App13Activity.m_View.getHolder().getSurface() );
        }
      }
    }
    ```

## 工作原理…

帧渲染回调在`App13Activity.java`中声明：

```kt
public static native void SetSurface( Surface surface );
public static native void SetSurfaceSize(
 int width, int height );
public static native void DrawFrame();
```

它们是`Wrappers.cpp`文件中实现的 JNI 调用：

```kt
JNIEXPORT void JNICALL
Java_com_packtpub_ndkcookbook_app13_App13Activity_SetSurface(
JNIEnv* env, jclass clazz, jobject javaSurface )
{
  if ( LGL3 ) { delete( LGL3 ); }
```

分配一个新的`sLGLAPI`结构并重新加载 OpenGL 函数的指针：

```kt
  LGL3 = new sLGLAPI;
  LGL::clGLExtRetriever* OpenGL;
  OpenGL = new LGL::clGLExtRetriever;
  OpenGL->Reload( LGL3 );
  delete( OpenGL );
}
JNIEXPORT void JNICALLJava_com_packtpub_ndkcookbook_app13_App13Activity_SetSurfaceSize(JNIEnv* env, jclass clazz, int Width, int Height )
{
```

更新表面大小。在这里我们不需要做其他任何事情，因为`SetSurface()`将在其后立即被调用：

```kt
  g_Width  = Width;
  g_Height = Height;
}
JNIEXPORT void JNICALLJava_com_packtpub_ndkcookbook_app13_App13Activity_DrawFrame(JNIEnv* env, jobject obj )
{
```

调用我们与平台无关的帧渲染回调：

```kt
  OnDrawFrame();
}
```

现在，我们可以将渲染代码放在`OnDrawFrame()`回调中，并在 Android 上使用它。

## 还有更多…

要使用之前讨论的代码，您需要在`AndroidManifest.xml`文件中添加这一行：

```kt
<uses-feature android:glEsVersion="0x00020000"/>
```

此外，您需要将本地应用程序与 OpenGL ES 2 或 OpenGL ES 3 库链接。在您的`Android.mk`文件中放入`-lGLESv2`或`-lGLESv3`开关，如下所示：

```kt
LOCAL_LDLIBS += -lGLESv2
```

### 注意

还有一种方法可以做到这一点。您可以省略静态链接，通过`dlopen()`调用打开`libGLESv2.so`共享库，并使用`dlsym()`函数获取 OpenGL 函数的指针。如果您正在开发适用于 OpenGL ES 2 和 OpenGL ES 3 的通用渲染器，并希望运行时调整一切，这很有用。

## 另请参阅

+   *统一 OpenGL 3 核心配置和 OpenGL ES 2*

# 统一 GLSL 3 和 GLSL ES 2 着色器

OpenGL 3 支持 OpenGL 着色语言。特别是，OpenGL 3.2 Core Profile 支持 GLSL 1.50 Core Profile。另一方面，OpenGL ES 2 支持 GLSL ES 版本 1.0，而 OpenGL ES 3 支持 GLSL ES 3.0。这三个 GLSL 版本之间有轻微的语法差异，为了编写可移植的着色器，我们必须对这些差异进行抽象化处理。在本教程中，我们将创建一个设施，以将桌面 OpenGL 着色器降级，使其与 OpenGL ES 着色语言 1.0 兼容。

### 注意

OpenGL ES 3 对 OpenGL ES 着色语言 1.0 提供了向后兼容支持。为此，我们在着色器开头放置了`#version 100`。然而，如果你的应用程序只针对最新的 OpenGL ES 3，你可以使用标记`#version 300 es`并避免一些转换。更多详细信息，请参考 OpenGL ES 着色语言 3.0 的规格说明书，在[`www.khronos.org/registry/gles/specs/3.0/GLSL_ES_Specification_3.00.4.pdf`](http://www.khronos.org/registry/gles/specs/3.0/GLSL_ES_Specification_3.00.4.pdf)。

## 准备就绪

可以从官方 OpenGL 网站[`www.opengl.org`](http://www.opengl.org)下载不同版本的 GLSL 语言规格说明书。GLSL 1.50 规格说明书可以在[`www.opengl.org/registry/doc/GLSLangSpec.1.50.09.pdf`](http://www.opengl.org/registry/doc/GLSLangSpec.1.50.09.pdf)找到。

GLSL ES 的规格说明书可以从 Khronos 网站[`www.khronos.org`](http://www.khronos.org)下载。GLSL ES 1.0 规格说明书可在[`www.khronos.org/registry/gles/specs/2.0/GLSL_ES_Specification_1.0.17.pdf`](http://www.khronos.org/registry/gles/specs/2.0/GLSL_ES_Specification_1.0.17.pdf)获取。

## 如何操作…

1.  让我们看看两组简单的顶点和片段着色器。适用于 GLSL 1.50 的是：

    ```kt
    // vertex shader
    #version 150 core
    uniform mat4 in_ModelViewProjectionMatrix;
    in vec4 in_Vertex;
    in vec2 in_TexCoord;
    out vec2 Coords;
    void main()
    {
      Coords = in_TexCoord;
      gl_Position = in_ModelViewProjectionMatrix * in_Vertex;
    }

    // fragment shader
    #version 150 core
    in vec2 Coords;
    uniform sampler2D Texture0;
    out vec4 out_FragColor;
    void main()
    {
      out_FragColor = texture( Sampler0, Coords );
    }
    ```

1.  另一对着色器是针对 GLSL ES 1.0 的：

    ```kt
    // vertex shader
    #version 100
    precision highp float;
    uniform mat4 in_ModelViewProjectionMatrix;
    attribute vec4 in_Vertex;
    attribute vec2 in_TexCoord;
    varying vec2 Coords;
    void main()
    {
      Coords = in_TexCoord;
      gl_Position = in_ModelViewProjectionMatrix * in_Vertex;
    }

    // fragment shader
    #version 100
    precision highp float;
    uniform sampler2D Texture0;
    varying vec2 Coords;
    void main()
    {
      gl_FragColor = texture2D( Texture0, Coords );
    }
    ```

    下表是 OpenGL API 三个版本之间一些差异的摘要，需要抽象化处理：

    |   | OpenGL 3 | OpenGL ES 2 | OpenGL ES 3 |
    | --- | --- | --- | --- |
    | 版本定义 | #version 150 core | #version 100 | #version 300 es |
    | 显式浮点精度 | 不需要 | 需要 | 不需要 |
    | 变量和属性的关键字 | in 和 out | varying 和 attribute | in 和 out |
    | 固定功能片段数据位置 | 否，可定制 | gl_FragColor | 否，可定制 |
    | 2D 纹理获取 | texture()，重载 | texture2D() | texture()，重载 |

1.  让我们在以下代码中实现转换规则，以将 GLSL 1.50 着色器降级到 GLSL 1.0：

    ```kt
    #if defined( USE_OPENGL_3 )
    std::string ShaderStr = "#version 150 core\n";
    #else
    std::string ShaderStr = "#version 100\n";
    ShaderStr += "precision highp float;\n";
    ShaderStr += "#define USE_OPENGL_ES_2\n";
    ShaderCodeUsed = Str_ReplaceAllSubStr( ShaderCodeUsed,
      "texture(", "texture2D(" );
    if ( Target == GL_VERTEX_SHADER )
    {
        ShaderCodeUsed = Str_ReplaceAllSubStr( ShaderCodeUsed,"in ", "attribute " );
        ShaderCodeUsed = Str_ReplaceAllSubStr( ShaderCodeUsed,"out ", "varying " );
    }
    if ( Target == GL_FRAGMENT_SHADER )
    {
        ShaderCodeUsed = Str_ReplaceAllSubStr( ShaderCodeUsed,"out vec4 out_FragColor;", "" );
        ShaderCodeUsed = Str_ReplaceAllSubStr( ShaderCodeUsed,"out_FragColor", "gl_FragColor" );
        ShaderCodeUsed = Str_ReplaceAllSubStr( ShaderCodeUsed,"in ", "varying " );
    }
    #endif
    ```

    ### 注意

    这种搜索和替换暗示了对着色器源代码的一些限制。例如，它将使包含如`grayin`和`sprout`等标识符的着色器无效。然而，上述代码非常简单，并且已经在几个已发布的商业项目中成功使用。

我们将着色器以 GLSL 1.5 源代码的形式存储，并在 Android 上通过简单的搜索和替换来使用它们。这样做非常简单且透明。

## 工作原理…

完整的实现包含在`3_ShadersAndVertexArrays`示例中的`clGLSLShaderProgram`类中。代码降级后，如有需要，它会被上传到 OpenGL：

```kt
GLuint Shader = LGL3->glCreateShader( Target );
const char* Code = ShaderStr.c_str();
LGL3->glShaderSource( Shader, 1, &Code, NULL );
LOGI( "Compiling shader for stage: %X\n", Target );
LGL3->glCompileShader( Shader );
```

`CheckStatus()`函数执行错误检查，并在失败时记录指定的错误消息：

```kt
if ( !CheckStatus( Shader, GL_COMPILE_STATUS,"Failed to compile shader:" ) )
{
  LGL3->glDeleteShader( Shader );
  return OldShaderID;
}
if ( OldShaderID ) LGL3->glDeleteShader( OldShaderID );
return Shader;
```

`OldShaderID`保留了上一个编译的着色器。它用于允许在 PC 上即时编辑着色器，并防止加载无效着色器。在顶点和片段着色器编译之后，应该链接着色器程序：

```kt
bool clGLSLShaderProgram::RelinkShaderProgram()
{
  GLuint ProgramID = LGL3->glCreateProgram();
  FVertexShaderID = AttachShaderID( GL_VERTEX_SHADER,FVertexShader, FVertexShaderID );
  if ( FVertexShaderID ) LGL3->glAttachShader( ProgramID,FVertexShaderID );
  FFragmentShaderID = AttachShaderID( GL_FRAGMENT_SHADER,FFragmentShader, FFragmentShaderID );
  if ( FFragmentShaderID ) LGL3->glAttachShader( ProgramID,FFragmentShaderID );
  BindDefaultLocations( ProgramID );
  LGL3->glLinkProgram( ProgramID );
```

对着色器程序也应该执行相同的操作。只有当程序成功链接后，才替换旧的程序：

```kt
  if ( !CheckStatus( ProgramID, GL_LINK_STATUS,"Failed to link program\n" ) )
  {
    LOGI( "Error during shader program relinking\n" );
    return false;
  }
  LGL3->glDeleteProgram( FProgramID );
  FProgramID = ProgramID;
  RebindAllUniforms();
  return true;
}
```

我们必须绑定将在整个渲染器中使用不同属性的默认位置：

```kt
void clGLSLShaderProgram::BindDefaultLocations( GLuint ID )
{
```

`L_VS_`标识符的含义在*操作几何图形*的食谱中解释：

```kt
LGL3->glBindAttribLocation( ID, L_VS_VERTEX, "in_Vertex" );
LGL3->glBindAttribLocation( ID, L_VS_TEXCOORD,"in_TexCoord" );
LGL3->glBindAttribLocation( ID, L_VS_NORMAL, "in_Normal" );
LGL3->glBindAttribLocation( ID, L_VS_COLORS,  "in_Color" ); 
LGL3->glBindFragDataLocation( ID, 0, "out_FragColor" );
LGL3->glUniform1i(LGL3->glGetUniformLocation( ID, "Texture0" ), 0 );
}
```

现在着色器程序可以用于渲染了。

## 还有更多…

在渲染过程中，我们可以通过名称指定附加统一变量的位置，并要求底层 OpenGL API 通过名称绑定统一变量。然而，在我们自己的代码中这样做更方便，因为我们可以省略多余的 OpenGL 状态更改调用。以下是`RebindAllUniforms()`方法的清单，它将获取着色器程序中所有活跃统一变量的位置，并为以后的使用保存它们：

```kt
void clGLSLShaderProgram::RebindAllUniforms()
{
  Bind();
  FUniforms.clear();
  GLint ActiveUniforms;
  char Buff[256];
  LGL3->glGetProgramiv( FProgramID,GL_ACTIVE_UNIFORMS, &ActiveUniforms );
  for ( int i = 0; i != ActiveUniforms; ++i )
  {
    GLsizei Length;
    GLint   Size;
    GLenum  Type;
    LGL3->glGetActiveUniform( FProgramID, i,sizeof( Buff ), &Length, &Size, &Type, Buff );
    std::string Name( Buff, Length );
    sUniform Uniform( Name );
    Uniform.FLocation = LGL3->glGetUniformLocation(FProgramID, Name.c_str() );
    FUniforms.push_back( Uniform );
  }
}
```

`sUniform`是一个`struct`，它包含了一个活跃的统一变量：

```kt
struct sUniform
{
public:
  explicit sUniform( const std::string& Name )
  : FName( Name ), FLocation( -1 ) {}
  sUniform( int Location, const std::string& Name )
  : FName( Name ), FLocation( Location ) {}
  std::string FName;
  int         FLocation;
};
```

它在许多`SetUniformName()`函数中使用，以在运行时通过名称设置统一变量的值，而不接触 OpenGL API 来解决这些名称。

## 另请参阅

+   *操作几何图形*

+   *统一顶点数组*

+   *创建立即渲染的画布*

# 操作几何图形

在第四章，*组织虚拟文件系统*中，我们创建了`Bitmap`类以 API 无关的方式加载和存储位图。现在，我们将创建一个类似的抽象，用于几何数据的表示，稍后我们将使用它将顶点和它们的属性提交给 OpenGL。

## 准备就绪

在我们继续进行抽象之前，让我们先看看 OpenGL 中顶点规范是如何工作的。向 OpenGL 提交顶点数据需要你创建不同的**顶点流**，并指定它们的解释方式。如果你不熟悉这个概念，请参考教程：[`www.opengl.org/wiki/Vertex_Specification`](http://www.opengl.org/wiki/Vertex_Specification)。

## 如何操作…

我们必须决定将哪些**顶点属性**，或者说顶点流，存储在我们的**网格**中。假设对于一个给定的顶点，我们需要位置、纹理坐标、法线和颜色。

以下是这些流的名称和索引：

```kt
const int L_VS_VERTEX   = 0;
const int L_VS_TEXCOORD = 1;
const int L_VS_NORMAL   = 2;
const int L_VS_COLORS   = 3; 
const int L_VS_TOTAL_ATTRIBS = L_VS_COLORS + 1;
```

### 注意

有时可能需要额外的纹理坐标，例如，在多纹理算法中，或者额外的属性，如切线、副法线，或者在硬件加速的 GPU 蒙皮中用到的骨骼和权重。这些属性可以通过这些语义轻易引入。我们将此作为一个练习留给读者。

1.  让我们定义每个属性的浮点数组件数量：

    ```kt
    const int VEC_COMPONENTS[ L_VS_TOTAL_ATTRIBS ] = { 3, 2, 3, 4 };
    ```

    这意味着位置和法线以`vec3`表示，纹理坐标以`vec2`表示，颜色以`vec4`表示。我们需要这些信息以正确地在 OpenGL 着色器程序中定义类型并提交顶点数据。以下是我们用于顶点属性的渲染 API 无关容器的源代码：

    ```kt
    class clVertexAttribs: public iObject
    {
    public:
      clVertexAttribs();
      clVertexAttribs( size_t Vertices );
      void   SetActiveVertexCount( size_t Count ){ FActiveVertexCount = Count; }
      size_t GetActiveVertexCount() const{ return FActiveVertexCount; }
    ```

1.  我们需要一个方法将我们的顶点属性映射到枚举流：

    ```kt
      const std::vector<const void*>& EnumerateVertexStreams();
    ```

1.  我们还需要一些辅助方法来构建几何体：

    ```kt
      void Restart( size_t ReserveVertices );
      void EmitVertexV( const LVector3& Vec );
      void EmitVertex( float X, float Y, float Z ){ EmitVertexV( LVector3(X,Y,Z) ); };
      void SetTexCoord( float U, float V, float W ){ SetTexCoordV( LVector2(U,V) ); };
      void SetTexCoordV( const LVector2& V );
      void SetNormalV( const LVector3& Vec );
      void SetColorV( const LVector4& Vec );
    ```

1.  实际数据持有者为了方便被设置为`public`：

    ```kt
    public:
      // position X, Y, Z
      std::vector<LVector3> FVertices;
      // texture coordinate U, V
      std::vector<LVector2> FTexCoords;
      // normal in object space
      std::vector<LVector3> FNormals;
      // RGBA color
      std::vector<LVector4> FColors;
    …
    };
    ```

## 它是如何工作的…

为了使用`clVertexAttribs`并向其填充有用的数据，我们声明了一些辅助函数：

```kt
clPtr<clVertexAttribs> CreateTriangle2D( float vX, float vY,float dX, float dY, float Z );
clPtr<clVertexAttribs> CreateRect2D( float X1, float Y1, float X2,float Y2, float Z, bool FlipTexCoordsVertical,int Subdivide );
clPtr<clVertexAttribs> CreateAxisAlignedBox( const LVector3& Min,const LVector3& Max );
clPtr<clVertexAttribs> CreatePlane( float SizeX, float SizeY,int SegmentsX, int SegmentsY, float Z );
```

以下是这些定义中的一个示例：

```kt
clPtr<clVertexAttribs> clGeomServ::CreateTriangle2D( float vX,
 float vY, float dX, float dY, float Z )
{
 clPtr<clVertexAttribs> VA = new clVertexAttribs();
```

重新开始生成并分配`3`个顶点的空间：

```kt
 VA->Restart( 3 );
 VA->SetNormalV( LVector3( 0, 0, 1 ) );
 VA->SetTexCoord( 1, 1, 0 );
 VA->EmitVertexV( LVector3( vX   , vY   , Z ) );
 VA->SetTexCoord( 1, 0, 0 );
 VA->EmitVertexV( LVector3( vX   , vY - dY, Z ) );
 VA->SetTexCoord( 0, 1, 0 );
 VA->EmitVertexV( LVector3( vX + dX, vY   , Z ) );
 return VA;
}
```

这些函数的完整源代码可以在`3_ShadersAndVertexArrays`项目的`GeomServ.cpp`文件中找到。现在我们有一组方便的函数来创建简单的 2D 和 3D 几何原始物体，如单个三角形、矩形和盒子。

## 还有更多…

如果你想要学习如何创建更复杂的 3D 原始物体，请下载 Linderdaum Engine 的源代码（[`www.linderdaum.com`](http://www.linderdaum.com)）。在`Geometry/GeomServ.h`中，你会发现如何生成球体、管子、多面体、齿轮和其他 3D 物体。

## 另请参阅

+   *统一顶点数组*

# 统一顶点数组

几何数据通过顶点缓冲对象（**VBO**）和顶点数组对象（**VAO**）提交到 OpenGL 中。VBO 是 OpenGL 版本的组成部分；然而，VAO 不是 OpenGL ES 2 的一部分，但在 OpenGL 3.2 核心配置中是必须的。这意味着我们不得不进行另一层抽象，以隐藏两个 API 之间的差异。

> *一个**顶点缓冲对象**（**VBO**）是 OpenGL 的一个特性，它提供了上传顶点数据（位置、法线向量、颜色等）到视频设备的方法，用于非立即模式渲染。VBOs 比立即模式渲染提供了实质性的性能提升，主要是因为数据位于视频设备内存中，而不是系统内存中，因此可以直接由视频设备渲染。*

出处：[`en.wikipedia.org/wiki/Vertex_Buffer_Object`](http://en.wikipedia.org/wiki/Vertex_Buffer_Object)

> *一个**顶点数组对象**（**VAO**）是一个封装了指定顶点数据所需状态的 OpenGL 对象。它们定义了顶点数据的格式以及顶点数组的数据源。VAOs 不包含数组本身；数组存储在缓冲区对象中。VAOs 只是引用已经存在的缓冲对象。*

致谢：[`www.opengl.org/wiki/Vertex_Specification`](http://www.opengl.org/wiki/Vertex_Specification)

## 准备就绪

在继续使用顶点数组之前，请确保你已经熟悉了前一个食谱中与平台无关的几何存储。本食谱的源代码可以在`4_Canvas`示例中的`GLVertexArray.cpp`和`GLVertexArray.h`文件中找到。

## 如何操作…

1.  我们的顶点数组隐藏在`clGLVertexArray`类的接口后面：

    ```kt
    class clGLVertexArray: public iObject
    {
    public:
      clGLVertexArray();
      virtual ~clGLVertexArray();
      void Draw( bool Wireframe ) const;
      void SetVertexAttribs(const clPtr<clVertexAttribs>&Attribs);
    private:
      void Bind() const;
      GLuint FVBOID;
      GLuint FVAOID;
    ```

1.  通过以下代码存储 VBO 的偏移量：

    ```kt
      std::vector<const void*> FAttribVBOOffset;
    ```

1.  以下是附加的`clVertexAttribs`实际数据的指针：

    ```kt
      std::vector<const void*> FEnumeratedStreams;
      clPtr<clVertexAttribs> FAttribs;
    };
    ```

1.  应该使用`SetVertexAttribs()`方法将`clVertexAttribs`附加到我们的顶点数组上：

    ```kt
    void clGLVertexArray::SetVertexAttribs( constclPtr<clVertexAttribs>& Attribs )
    {
      FAttribs = Attribs;
      FEnumeratedStreams = FAttribs->EnumerateVertexStreams();
    ```

1.  我们必须在使用`FVBOID`之前移除任何旧的顶点缓冲对象，以允许重用`clGLVertexArray`：

    ```kt
      LGL3->glDeleteBuffers( 1, &FVBOID );
      size_t VertexCount = FAttribs->FVertices.size();
      size_t DataSize = 0;
      for ( int i = 0; i != L_VS_TOTAL_ATTRIBS; i++ )
      {
        FAttribVBOOffset[ i ] = ( void* )DataSize;
    ```

1.  计算顶点缓冲对象的大小并分配它：

    ```kt
        DataSize += FEnumeratedStreams[i] ?sizeof( float ) * L_VS_VEC_COMPONENTS[ i ] *
          VertexCount : 0;
      }
      LGL3->glGenBuffers( 1, &FVBOID );
      LGL3->glBindBuffer( GL_ARRAY_BUFFER, FVBOID );
      LGL3->glBufferData( GL_ARRAY_BUFFER, DataSize,NULL, GL_STREAM_DRAW );
    ```

1.  为每个顶点属性提交数据：

    ```kt
      for ( int i = 0; i != L_VS_TOTAL_ATTRIBS; i++ )
      {
        LGL3->glBufferSubData( GL_ARRAY_BUFFER,(GLintptrARB)FAttribVBOOffset[ i ],FAttribs->GetActiveVertexCount() *sizeof( float ) * L_VS_VEC_COMPONENTS[ i ],FEnumeratedStreams[ i ] );
      }
    ```

1.  如果我们不在 Android 上，这里将创建 VAO：

    ```kt
    #if !defined( ANDROID )
      LGL3->glBindVertexArray( FVAOID );
      Bind();
      LGL3->glBindVertexArray( 0 );
    #endif
    }
    ```

    ### 注意

    VAO 可以与 OpenGL ES 3 一起使用。我们将它们的实现留给读者作为一个简单的练习。这可以通过为 OpenGL ES 3 使用 OpenGL 3 的代码路径来完成。

## 工作原理…

`Bind()`方法负责实际绑定顶点缓冲对象并准备属性指针：

```kt
void clGLVertexArray::Bind() const
{
  LGL3->glBindBuffer( GL_ARRAY_BUFFER, FVBOID );
  LGL3->glVertexAttribPointer( L_VS_VERTEX,L_VS_VEC_COMPONENTS[ 0 ], GL_FLOAT, GL_FALSE, 0,FAttribVBOOffset[ 0 ] );
  LGL3->glEnableVertexAttribArray( L_VS_VERTEX );

  for ( int i = 1; i < L_VS_TOTAL_ATTRIBS; i++ )
  {
    LGL3->glVertexAttribPointer( i,L_VS_VEC_COMPONENTS[ i ],GL_FLOAT, GL_FALSE, 0,FAttribVBOOffset[ i ] );

    FAttribVBOOffset[ i ] ?LGL3->glEnableVertexAttribArray( i ) :LGL3->glDisableVertexAttribArray( i );
  }
}
```

现在，我们可以通过`Draw()`方法渲染几何图形：

```kt
void clGLVertexArray::Draw( bool Wireframe ) const
{
#if !defined( ANDROID )
  LGL3->glBindVertexArray( FVAOID );
#else
  Bind();
#endif
  LGL3->glDrawArrays( Wireframe ? GL_LINE_LOOP : GL_TRIANGLES,0, static_cast<GLsizei>(FAttribs->GetActiveVertexCount() ) );
}
```

再次提醒，有一个`#define`用于在 Android 上禁用 VAO。以下是在本章所有前一个食谱的技术基础上，使用`3_ShadersAndVertexArrays`示例渲染一个动画旋转立方体的截图：

![工作原理…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_06_2.jpg)

## 还有更多…

我们始终假设在所有示例中，每个顶点属性（位置、纹理坐标、法线和颜色）都存在于几何数据中。实际上，这对于我们的`clVertexAttribs`实现来说总是正确的。然而，在更复杂的情况下，例如你可能需要更多的顶点属性，比如副法线、切线、骨骼权重等，为未使用的属性分配内存是不明智的。这可以通过修改`clVertexAttribs::EnumerateVertexStreams()`成员函数，并在`Bind()`和`SetVertexAttribs()`中添加 NULL 检查来实现。

## 另请参阅

+   *操纵几何图形*

# 创建纹理的包装器

在前面的章节中，我们已经使用 OpenGL 纹理将离屏帧缓冲区渲染到屏幕上。但是，那条代码路径只在 Android 上有效，不能在桌面上使用。在本食谱中，我们将创建一个纹理包装器，使它们可移植。

## 准备就绪

查看`4_Canvas`中的`GLTexture.cpp`和`GLTexture.h`文件。

## 如何操作…

1.  让我们声明一个类来保存 OpenGL 纹理。我们只需要两个公共操作：从位图中加载像素数据，以及将纹理绑定到指定的 OpenGL 纹理单元：

    ```kt
    class clGLTexture
    {
    public:
      clGLTexture();
      virtual ~clGLTexture();
      void    Bind( int TextureUnit ) const;
      void    LoadFromBitmap( const clPtr<clBitmap>& B );
    private:
      GLuint         FTexID;
      GLenum         FInternalFormat;
      GLenum         FFormat;
    }
    ```

1.  这个类的接口非常简单，因为 OpenGL ES 2 和 OpenGL 3 中的纹理管理几乎相同。所有差异都在实现中。以下代码展示了我们如何绑定纹理：

    ```kt
    void clGLTexture::Bind( int TextureUnit ) const
    {	
      LGL3->glActiveTexture( GL_TEXTURE0 + TextureUnit );
      LGL3->glBindTexture( GL_TEXTURE_2D, FTexID );
    }
    ```

1.  我们通过以下代码从位图加载纹理：

    ```kt
    void clGLTexture::LoadFromBitmap( const clPtr<clBitmap>& B )
    {
      if ( !FTexID ) LGL3->glGenTextures( 1, &FTexID );
      ChooseInternalFormat( B->FBitmapParams, &FFormat,&FInternalFormat );
      Bind( 0 );
      LGL3->glTexParameteri( GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER, GL_LINEAR );
      LGL3->glTexParameteri( GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER, GL_LINEAR );
    ```

1.  OpenGL ES 2 并不支持所有的纹理包装模式。特别是，`GL_CLAMP_TO_BORDER`是不支持的：

    ```kt
    #if defined( ANDROID )
    LGL3->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S,GL_CLAMP_TO_EDGE );
      LGL3->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T,GL_CLAMP_TO_EDGE );
    #else
    LGL3->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S,GL_CLAMP_TO_BORDER );
    LGL3->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T,GL_CLAMP_TO_BORDER );
    #endif
      LGL3->glTexImage2D( GL_TEXTURE_2D, 0, FInternalFormat,B->GetWidth(), B->GetHeight(), 0, FFormat,GL_UNSIGNED_BYTE, B->FBitmapData );
    }
    ```

1.  有一个辅助函数`ChooseInternalFormat()`，我们用它来为位图选择合适的 OpenGL 图像格式，无论是 RGB 还是 RGBA。实现如下所示代码：

    ```kt
    bool ChooseInternalFormat( const sBitmapParams& BMPRec,
    GLenum* Format, GLenum* InternalFormat )
    {
      if ( BMPRec.FBitmapFormat == L_BITMAP_BGR8 )
      {
    #if defined( ANDROID )
        *InternalFormat = GL_RGB;
        *Format = GL_RGB;
    #else
        *InternalFormat = GL_RGB8;
        *Format = GL_BGR;
    #endif
      }
    ```

1.  这同样适用于包含 alpha 通道的 RGBA 位图：

    ```kt
      if ( BMPRec.FBitmapFormat == L_BITMAP_BGRA8 )
      {
    #if defined( ANDROID )
        *InternalFormat = GL_RGBA;
        *Format = GL_RGBA;
    #else
        *InternalFormat = GL_RGBA8;
        *Format = GL_BGRA;
    #endif
      }
      return false;
    }
    ```

这个函数可以很容易地扩展以支持灰度、浮点数和压缩格式。

## 工作原理…

使用我们的纹理包装器非常直接：

```kt
  clPtr<clBitmap> Bmp = clBitmap::LoadImg(g_FS->CreateReader("test.bmp") );
  Texture = new clGLTexture();
  Texture->LoadFromBitmap( Bmp );
```

在这里，`g_FS`是一个在第五章，*跨平台音频流*中创建的`FileSystem`对象。

## 还有更多…

到目前为止我们处理的纹理加载是同步的，并且是在主渲染线程上执行的。如果我们只有几个位图要加载，这是可以接受的。现实世界的方法是在另一个线程上异步加载和解码图像，然后在渲染线程上只调用`glTexImage2D()`和其他相关的 OpenGL 命令。我们将在第九章，*编写一个拼图游戏*中学习如何做到这一点。

## 另请参阅

+   第四章，*组织一个虚拟文件系统*

+   第九章，*编写一个拼图游戏*

# 创建一个用于即时渲染的画布

在前面的食谱中，我们学习了如何为主要的 OpenGL 实体制作抽象：顶点缓冲区、着色器程序和纹理。这个基础足以使用 OpenGL 渲染许多复杂的特效。然而，有许多小的渲染任务，你只需要渲染一个三角形或带有一个纹理的矩形，或者使用特定的着色器渲染一个全屏四边形以应用一些图像空间效果。在这种情况下，管理缓冲区、着色器和纹理的代码可能成为一个严重的负担。让我们为这样的辅助代码组织一个地方，即一个画布，它可以帮助我们用一行代码渲染简单的事物。

## 准备就绪

本食谱使用了前一个食谱中描述的`clGLSLShaderProgram`、`clGLTexture`和`clGLVertexArray`类，以隐藏 OpenGL ES 2 和 OpenGL 3 之间的差异。在继续之前请仔细阅读它们。

## 如何操作…

1.  我们首先定义一个`clCanvas`类如下：

    ```kt
    class clCanvas
    {
    public:
      clCanvas();
      virtual ~clCanvas() {};
      void Rect2D( float X1, float Y1,float X2, float Y2, const LVector4& Color );
      void TexturedRect2D( float X1, float Y1,float X2, float Y2,const LVector4& Color,const clPtr<clGLTexture>& Texture );
      clPtr<clGLVertexArray> GetFullscreenRect() const
      { return FRectVA; }
    ```

1.  我们在这里存储一些与 OpenGL 相关的实体：

    ```kt
    private:
      clPtr<clVertexAttribs> FRect;
      clPtr<clGLVertexArray> FRectVA;
      clPtr<clGLSLShaderProgram> FRectSP;
      clPtr<clGLSLShaderProgram> FTexRectSP;
    };
    ```

1.  在使用画布之前，我们必须构建它。注意`FRect`是作为一个全屏四边形创建的：

    ```kt
    clCanvas::clCanvas()
    {
      FRect = clGeomServ::CreateRect2D( 0.0f, 0.0f,1.0f, 1.0f, 0.0f, false, 1 );
      FRectVA = new clGLVertexArray();
      FRectVA->SetVertexAttribs( FRect );
      FRectSP = new clGLSLShaderProgram( RectvShaderStr,RectfShaderStr );
      FTexRectSP = new clGLSLShaderProgram( RectvShaderStr,
        TexRectfShaderStr );
    }
    ```

1.  我们在下面的顶点着色器中重新映射`FRect`的坐标，使它们与用户指定的尺寸相匹配：

    ```kt
       uniform vec4 u_RectSize;
       in vec4 in_Vertex;
       in vec2 in_TexCoord;
       out vec2 Coords;
       void main()
       {
          Coords = in_TexCoord;
          float X1 = u_RectSize.x;
          float Y1 = u_RectSize.y;
          float X2 = u_RectSize.z;
          float Y2 = u_RectSize.w;
          float Width  = X2 - X1;
          float Height = Y2 - Y1;
          vec4 VertexPos = vec4( X1 + in_Vertex.x * Width,Y1 + in_Vertex.y * Height,in_Vertex.z, in_Vertex.w ) *vec4( 2.0, -2.0, 1.0, 1.0 ) +vec4( -1.0, 1.0, 0.0, 0.0 );
          gl_Position = VertexPos;
       }
    ```

1.  实际尺寸，指定为矩形的左上角和右下角，作为`u_RectSize`统一变量的`xyzw`组件传递。简单的算术完成了剩余的工作。片段着色器非常简单。实际上，我们只需要从统一变量中应用一种纯色：

    ```kt
    uniform vec4 u_Color;
    out vec4 out_FragColor;
    in vec2 Coords;
    void main()
    {
      out_FragColor = u_Color;
    }
    ```

1.  或者，从纹理应用额外的颜色：

    ```kt
    uniform vec4 u_Color;
    out vec4 out_FragColor;
    in vec2 Coords;
    uniform sampler2D Texture0;
    void main()
    {
      out_FragColor = u_Color * texture( Texture0, Coords );
    }
    ```

我们使用前一个食谱中的`clGLSLShaderProgram`类来设置着色器程序。它隐藏了 OpenGL ES 2 和 OpenGL 3 之间的语法差异，因此我们可以只存储每个着色器的一个版本。

### 注意

你可以尝试实现一个类似 OpenGL ES 3 的包装器作为练习。

## 它是如何工作的…

1.  画布内部的实际渲染代码非常简单。绑定纹理和着色器程序，设置统一变量的值，并绘制顶点数组：

    ```kt
    void clCanvas::TexturedRect2D(
     float X1, float Y1,
     float X2, float Y2,
     const LVector4& Color,
     const clPtr<clGLTexture>& Texture )
    {
      LGL3->glDisable( GL_DEPTH_TEST );
      Texture->Bind(0);
      FTexRectSP->Bind();
      FTexRectSP->SetUniformNameVec4Array(
        "u_Color", 1, Color );
      FTexRectSP->SetUniformNameVec4Array(
        "u_RectSize", 1, LVector4( X1, Y1, X2, Y2 ) );
      LGL3->glBlendFunc(
        GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA );
      LGL3->glEnable( GL_BLEND );
      FRectVA->Draw( false );
      LGL3->glDisable( GL_BLEND );
    }
    ```

### 注意

在这里我们总是启用和禁用混合。这导致了冗余的状态变化。更好的方法是保存先前设置的混合模式的值，并且只在必要时切换它。

完整的源代码在`4_Canvas`项目中的`Canvas.cpp`和`Canvas.h`文件中。画布的使用非常简单。例如，使用以下单行调用以渲染半透明的洋红色矩形：

```kt
Canvas->Rect2D( 0.1f, 0.1f, 0.5f, 0.5f, vec4( 1, 0, 1, 0.5f ) );
```

示例`4_Canvas`展示了如何使用画布，并生成与以下类似的图像，该图像展示了使用`Canvas`的叠加渲染：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_06_3.jpg)

## 还有更多…

画布为不同的即时渲染函数提供了占位符。在接下来的两章中，我们将为其增加其他方法，以渲染我们游戏的用户界面。

## 另请参阅

+   *统一 OpenGL 3 核心配置文件和 OpenGL ES 2*

+   *统一 GLSL 3 和 GLSL ES 2 着色器*

+   *统一顶点数组*

+   *为纹理创建包装器*
