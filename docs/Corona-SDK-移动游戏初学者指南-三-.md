# Corona SDK 移动游戏初学者指南（三）

> 原文：[`zh.annas-archive.org/md5/A062C0ACF1C6EB24D4DCE7039AD45F82`](https://zh.annas-archive.org/md5/A062C0ACF1C6EB24D4DCE7039AD45F82)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：播放声音和音乐

> *我们在日常生活中遇到的几乎所有类型的媒体中都能听到声音效果和音乐。许多著名游戏如*《吃豆人》*、*《愤怒的小鸟》*和*《水果忍者》*仅凭它们的主题音乐或声音效果就能被识别出来。除了我们在游戏中看到的视觉图像，声音帮助影响故事情节中传达的情绪和/或游戏过程中的氛围。与游戏主题相关的优质声音效果和音乐，有助于给体验带来真实感。*

在本章中，你将学习如何为你的应用程序添加声音效果和音乐。在前面章节中创建 Breakout 和 Panda Star Catcher 时，你已经掌握了视觉吸引力。现在，让我们为我们的耳朵提升感官体验！

你将要学习的主要内容包括：

+   加载、播放和循环音频

+   了解如何播放、暂停、恢复、倒带和停止音频

+   内存管理（处理音频）

+   音量控制

+   性能和编码技巧

让我们创造更多的魔法！

# Corona 音频系统

Corona 音频系统具有先进的**开放音频库**（**OpenAL**）功能。OpenAL 专为高效渲染多通道三维定位音频而设计。OpenAL 的一般功能编码在源对象、音频缓冲区和单一监听器中。源对象包含指向缓冲区的指针、声音的速度、位置和方向，以及声音的强度。缓冲区包含 PCM 格式的音频数据，可以是 8 位或 16 位，单声道或立体声格式。监听器对象包含监听者的速度、位置和方向，以及应用于所有声音的总增益。

### 注意

想要了解更多关于 Corona 音频系统的信息，你可以访问[`developer.coronalabs.com/partner/audionotes`](http://developer.coronalabs.com/partner/audionotes)。关于 OpenAL 的一般信息可以在[`www.openal.org`](http://www.openal.org)找到。

## 声音格式

以下是与 iOS 和安卓平台兼容的声音格式：

+   所有平台都支持 16 位、小端、线性的`.wav`格式文件

+   iOS 支持`.mp3`、`.aif`、`.caf`和`.aac`格式

+   Mac 模拟器支持`.mp3`、`.aif`、`.caf`、`.ogg`和`.aac`格式

+   Windows 模拟器支持`.mp3`和`.ogg`格式

+   安卓支持`.mp3`和`.ogg`格式

## 安卓上的声音文件名限制

在 Android 构建时，文件扩展名被忽略，因此无论扩展名如何，文件都被视为相同。目前的解决办法是更改文件名以区分扩展名。请参阅以下列出的示例：

+   `tap_aac.aac`

+   `tap_aif.aif`

+   `tap_caf.caf`

+   `tap_mp3.mp3`

+   `tap_ogg.ogg`

## 单声道声音效果最佳

使用单声道声音比立体声声音节省一半的内存。由于 Corona 音频系统使用 OpenAL，它只会对单声道声音应用空间化/3D 效果。OpenAL 不对立体声样本应用 3D 效果。

## 同时播放的最大通道数

可以运行的最大通道数为 32，这使得最多可以同时播放 32 个不同的声音。在你的代码中查看结果通道数的 API 是 `audio.totalChannels`。

# 是时候播放音乐了

音频可以通过以下两种不同的方式加载：

+   `loadSound()`: 这会将整个声音预加载到内存中

+   `loadStream()`: 这会分小块读取声音以节省内存，准备播放

## audio.loadSound()

`audio.loadSound()`函数将整个文件完全加载到内存中，并返回对音频数据的引用。完全加载到内存中的文件可以重复使用、播放，并同时在多个通道上共享。因此，你只需要加载文件的单一实例。在游戏中用作音效的声音将属于这一类。

语法为 `audio.loadSound(audiofileName [, baseDir ])`。

参数如下：

+   `audiofileName`: 这指定了你想要加载的音频文件的名称。支持的文件格式取决于运行该文件的平台。

+   `baseDir`: 默认情况下，声音文件应位于应用程序资源目录中。如果声音文件位于应用程序文档目录中，请使用 `system.DocumentsDirectory`。

例如：

+   `tapSound = audio.loadSound("tap.wav")`

+   `smokeSound = audio.loadSound("smoke.mp3")`

## audio.loadStream()

`audio.loadStream()`函数用于加载一个文件，以流的形式读取。流式文件是分小块读取的，以最小化内存使用。对于体积大、时长长的文件，这种方式非常理想。这些文件不能同时在多个通道间共享。如果需要，你必须加载该文件的多个实例。

语法为 `audio.loadStream( audioFileName [, baseDir ] )`

参数如下：

+   `audiofileName`: 这指定了你想要加载的音频文件的名称。支持的文件格式取决于运行该文件的平台。

+   `baseDir`: 默认情况下，声音文件应位于应用程序资源目录中。如果声音文件位于应用程序文档目录中，请使用 `system.DocumentsDirectory`。

例如：

+   `music1 = audio.loadStream("song1.mp3")`

+   `music2 = audio.loadStream("song2.wav")`

## audio.play()

`audio.play()`函数在通道上播放由音频句柄指定的音频。如果没有指定通道，将自动为你选择一个可用通道。函数返回音频播放的通道号。

语法为 `audio.play( audioHandle [, options ] )`

参数如下：

+   `audioHandle`: 这是你想播放的音频数据

+   `options`：这是播放的附加选项，格式为表。

`options` 的参数：

+   `channel`：这个选项允许你选择希望音频播放的通道号。从 1 到最大通道数 32 都是有效的通道。如果你指定 0 或省略，系统将自动为你选择通道。

+   `loops`：这个选项允许你选择音频循环的次数。0 表示不循环，意味着声音将播放一次并不循环。-1 表示系统将无限循环样本。

+   `duration`：这个选项以毫秒为单位，它将使系统播放指定时间的音频。

+   `fadein`：这个选项以毫秒为单位，它将使声音从最小通道音量开始播放，并在指定毫秒数内过渡到正常通道音量。

+   `onComplete`：这是一个回调函数，当播放结束时将被调用。`onComplete` 回调函数会传递一个事件参数。

例如：

```kt
backgroundMusic = audio.loadStream("backgroundMusic.mp3")
backgroundMusicChannel = audio.play( backgroundMusic, { channel=1, loops=-1, fadein=5000 }  )  
-- play the background music on channel 1, loop infinitely, and fadein over 5 seconds
```

## 循环

高度压缩的格式，如 MP3、AAC 和 Ogg Vorbis，可能会移除音频样本末端的采样点，可能会破坏正确循环的剪辑。如果你在播放过程中遇到循环间隙，请尝试使用 WAV（兼容 iOS 和 Android）。确保你的引导和结束点干净清晰。

## 同时播放

通过 `loadSound()` 加载的声音可以在多个通道上同时播放。例如，你可以如下加载一个音效：

```kt
bellSound = audio.loadSound("bell.wav")
```

如果你想要为多个对象产生各种铃声，你可以这么做。音频引擎经过高度优化，可以处理这种情况。使用相同的句柄调用 `audio.play()`，次数可达最大通道数（32 次）：

```kt
audio.play(bellSound)
audio.play(bellSound)
audio.play(bellSound)
```

# 动手操作时间 – 播放音频

我们将学习声音效果和音乐在 Corona 中的实现方式，以了解它实际是如何工作的。要播放音频，请按照以下步骤操作：

1.  在你的桌面上创建一个名为 `Playing Audio` 的新项目文件夹。

1.  在 `Chapter 6 Resources` 文件夹中，将 `ring.wav` 和 `song1.mp3` 声音文件复制到你的项目文件夹中，并创建一个新的 `main.lua` 文件。你可以从 Packt Publishing 网站下载伴随这本书的项目文件。

1.  使用 `loadSound()` 和 `loadStream()` 预加载以下音频：

    ```kt
    ringSound = audio.loadSound( "ring.wav" )
    backgroundSound = audio.loadStream( "song1.mp3" )
    ```

1.  将 `backgroundSound` 设置为通道 1，无限循环，并在 3 秒后淡入：

    ```kt
    mySong = audio.play( backgroundSound, { channel=1, loops=-1, fadein=3000 }  )
    ```

1.  添加 `ringSound` 并播放一次：

    ```kt
    myRingSound = audio.play( ringSound )
    ```

1.  保存项目并在 Corona 模拟器中运行，以听取结果。

## *刚才发生了什么？*

对于仅是短音效的音频，我们使用 `audio.loadSound()` 来准备声音。对于大小较大或时长较长的音频，使用 `audio.loadStream()`。

`backgroundSound` 文件设置为通道 1，并在开始播放 3 秒后淡入。`loops = -1` 表示文件将无限循环从开始到结束。

## 尝试英雄 – 延迟重复音频

如你所见，加载和播放音频真的很简单。只需两行代码就可以播放一个简单的声音。让我们看看你是否能把它提升一个档次。

使用 `ring.wav` 文件并通过 `loadSound()` 加载它。创建一个播放音频的函数。让声音每 2 秒播放一次，重复五次。

# 是时候掌控一切了

现在我们可以在模拟器中播放它们，因此我们有能力控制我们的声音。回想一下卡带播放器的日子，它有暂停、停止和倒带等功能。Corona 的音频 API 库也可以做到这一点。

## audio.stop()

`audio.stop()` 函数会停止通道上的播放并清除通道，以便可以再次播放。

语法为 `audio.stop( [channel] )` 或 `audio.stop( [ { channel = c } ] )`。

不带参数会停止所有活动通道。`channel` 参数指定要停止的通道。指定 0 会停止所有通道。

## audio.pause()

`audio.pause()` 函数会在通道上暂停播放。这对没有播放的通道没有影响。

语法为 `audio.pause( [channel] )` 或 `audio.pause( [ {channel = c} ] )`。

不带参数会暂停所有活动通道。`channel` 参数指定要暂停的通道。指定 0 会暂停所有通道。

## audio.resume()

`audio.resume()` 函数会恢复暂停的通道上的播放。这对没有暂停的通道没有影响。

语法为 `audio.pause( [channel] )` 或 `audio.pause( [ {channel = c} ] )`。

不带参数会恢复所有暂停的通道。`channel` 参数指定要恢复的通道。指定 0 会恢复所有通道。

## audio.rewind()

`audio.rewind()` 函数会将音频倒带到活动通道或直接在音频句柄上的开始位置。

语法为 `audio.rewind( [, audioHandle ] [, { channel=c } ] )`。

参数如下：

+   `audioHandle`：`audioHandle` 参数允许你倒带所需的数据。它最适合用 `audio.loadStream()` 加载的音频。不要尝试与 `channel` 参数在同一调用中使用。

+   `channel`：`channel` 参数允许你选择要应用倒带操作的通道。它最适合用 `audio.loadSound()` 加载的音频。不要尝试与 `audioHandle` 参数在同一调用中使用。

# 行动时间 – 控制音频

让我们通过创建用户界面按钮来模拟我们自己的小音乐播放器，以下面的方式控制音频调用：

1.  在 `Chapter 6` 文件夹中，将 `Controlling Audio` 项目文件夹复制到你的桌面。你会注意到有几个艺术资源，一个 `ui.lua` 库，一个 `config.lua` 文件，以及一个 `song2.mp3` 文件。你可以从 Packt Publishing 网站下载本书附带的的项目文件。![行动时间 – 控制音频](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_06_01.jpg)

1.  在同一个项目文件夹中，创建一个全新的 `main.lua` 文件。

1.  通过 `loadStream()` 加载音频文件，将其命名为 `music`，并调用 UI 库。还在一个名为 `myMusic` 的局部变量中添加它：

    ```kt
    local ui = require("ui")
    local music = audio.loadStream( "song2.mp3" ) local myMusicChannel
    ```

1.  创建一个名为 `onPlayTouch()` 的局部函数，带有一个 `event` 参数以播放音频文件。添加一个包含 `event.phase == "release"` 的 `if` 语句，以便在按钮释放时开始播放音乐。将 `playBtn` 显示对象作为一个新的 UI 按钮应用：

    ```kt
    local onPlayTouch = function( event )
      if event.phase == "release" then
        myMusicChannel = audio.play( music, { loops=-1 }  )
      end
    end

    playBtn = ui.newButton{
      defaultSrc = "playbtn.png",
      defaultX = 100,
      defaultY = 50,
      overSrc = "playbtn-over.png",
      overX = 100,
      overY = 50,
      onEvent = onPlayTouch,
      id = "PlayButton",
      text = "",
      font = "Helvetica",
      size = 16,
      emboss = false
    }

    playBtn.x = 160; playBtn.y = 100
    ```

1.  创建一个名为 `onPauseTouch()` 的局部函数，带有一个 `event` 参数以暂停音频文件。当 `event.phase == "release"` 时添加一个 `if` 语句，以便音乐暂停。将 `pauseBtn` 显示对象作为一个新的 UI 按钮应用：

    ```kt
    local onPauseTouch = function( event )
      if event.phase == "release" then
        audio.pause( myMusicChannel )
        print("pause")
      end
    end

    pauseBtn = ui.newButton{
      defaultSrc = "pausebtn.png",
      defaultX = 100,
      defaultY = 50,
      overSrc = "pausebtn-over.png",
      overX = 100,
      overY = 50,
      onEvent = onPauseTouch,
      id = "PauseButton",
      text = "",
      font = "Helvetica",
      size = 16,
      emboss = false
    }

    pauseBtn.x = 160; pauseBtn.y = 160
    ```

1.  添加一个名为 `onResumeTouch()` 的局部函数，带有一个 `event` 参数以恢复音频文件。当 `event.phase == "release"` 时添加一个 `if` 语句，以便音乐恢复。将 `resumeBtn` 显示对象作为一个新的 UI 按钮应用：

    ```kt
    local onResumeTouch = function( event )
      if event.phase == "release" then
        audio.resume( myMusicChannel )
        print("resume")
      end
    end

    resumeBtn = ui.newButton{
      defaultSrc = "resumebtn.png",
      defaultX = 100,
      defaultY = 50,
      overSrc = "resumebtn-over.png",
      overX = 100,
      overY = 50,
      onEvent = onResumeTouch,
      id = "ResumeButton",
      text = "",
      font = "Helvetica",
      size = 16,
      emboss = false
    }

    resumeBtn.x = 160; resumeBtn.y = 220
    ```

1.  添加一个名为 `onStopTouch()` 的局部函数，带有一个 `event` 参数以停止音频文件。当 `event.phase == "release"` 时创建一个 `if` 语句，以便音乐停止。将 `stopBtn` 显示对象作为一个新的 UI 按钮应用：

    ```kt
    local onStopTouch = function( event )
      if event.phase == "release" then
        audio.stop() 
        print("stop")

      end
    end

    stopBtn = ui.newButton{
      defaultSrc = "stopbtn.png",
      defaultX = 100,
      defaultY = 50,
      overSrc = "stopbtn-over.png",
      overX = 100,
      overY = 50,
      onEvent = onStopTouch,
      id = "StopButton",
      text = "",
      font = "Helvetica",
      size = 16,
      emboss = false
    }

    stopBtn.x = 160; stopBtn.y = 280
    ```

1.  添加一个名为 `onRewindTouch()` 的局部函数，带有一个 `event` 参数以倒带音频文件。当 `event.phase == "release"` 时创建一个 `if` 语句，以便音乐倒带到曲目开头。将 `rewindBtn` 显示对象作为一个新的 UI 按钮应用：

    ```kt
    local onRewindTouch = function( event )
      if event.phase == "release" then
        audio.rewind( myMusicChannel )
        print("rewind")
      end
    end

    rewindBtn = ui.newButton{
      defaultSrc = "rewindbtn.png",
      defaultX = 100,
      defaultY = 50,
      overSrc = "rewindbtn-over.png",
      overX = 100,
      overY = 50,
      onEvent = onRewindTouch,
      id = "RewindButton",
      text = "",
      font = "Helvetica",
      size = 16,
      emboss = false
    }

    rewindBtn.x = 160; rewindBtn.y = 340
    ```

1.  保存你的项目并在模拟器中运行。现在你已经创建了一个功能齐全的媒体播放器！！![行动时间——控制音频](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_06_02.jpg)

## *刚才发生了什么？*

我们通过调用 `require("ui")` 为我们的用户界面按钮添加了一个 UI 库。这会在按钮被按下时产生按下时的外观。

创建了各种功能来运行每个按钮。它们如下：

+   `onPlayTouch()`：当用户按下按钮触发事件时，调用 `myMusicChannel = audio.play( music, { loops=-1 } )`

+   `onPauseTouch()`：当按下按钮时，调用 `audio.pause( myMusicChannel )` 暂停歌曲

+   `onResumeTouch()`：如果歌曲已经被暂停，调用 `audio.resume( myMusicChannel )` 恢复歌曲

+   `onStopTouch()`：如果歌曲当前正在播放，调用 `audio.stop()` 停止音频

+   `onRewindTouch()`：调用 `audio.rewind( myMusicChannel )` 将歌曲倒带到曲目开头。

### 注意

当一首歌曲被暂停时，只有按下**恢复**按钮才会继续播放。当按下**暂停**按钮时，**播放**按钮将不起作用。

# 内存管理

当你完全完成音频文件时，调用 `audio.dispose()` 非常重要。这样做可以让你回收内存。

## audio.dispose()

`audio.dispose()` 函数释放与句柄关联的音频内存。

语法是 `audio.dispose( audioHandle )`。

参数如下：

+   `audioHandle`：由你想要释放的 `audio.loadSound()` 或 `audio.loadStream()` 函数返回的句柄。

    ### 提示

    在释放内存后，你一定不能使用该句柄。当尝试释放音频时，音频不应该在任何通道上播放或暂停。

例如：

```kt
mySound = audio.loadSound( "sound1.wav" )
myMusic = audio.loadStream( "music.mp3" )

audio.dispose( mySound )
audio.dispose( myMusic )

mySound = nil
myMusic = nil
```

## 尝试英雄——处理音频

你刚刚学会了如何正确处理音频文件，以便在应用程序中回收内存。尝试以下操作：

+   加载你的音频文件，并让它播放指定的时间。创建一个函数，当调用`onComplete`命令时处理文件。

+   在`控制音频`项目文件中，在`onStopTouch()`函数中处理音频。

# 音频更改

音频系统还具备更改音频音量的最小和最大状态的能力，以及在需要时淡入淡出音频。

## 音量控制

音频的音量可以设置为 0 到 1.0 之间的值。此设置可以在扩展声音播放之前或播放期间的任何时间调整。

### audio.setVolume()

`audio.setVolume`函数设置音量。

语法是 `audio.setVolume( volume [, [options] ] ) -- 成功后，应返回 true`。

参数如下：

+   `volume`：这允许你设置想要应用的音量级别。有效的数字范围从 0.0 到 1.0，其中 1.0 是最大音量值。默认音量基于你的设备铃声音量，并会有所不同。

+   `options`：这是一个支持你想要设置音量的通道号的表。你可以设置 1 到 32 之间的任何通道的音量。指定 0 以将音量应用到所有通道。完全省略此参数将设置主音量，这与通道音量不同。

例如：

+   `audio.setVolume( 0.75 ) -- 设置主音量`

+   `audio.setVolume( 0.5, { channel=2 } ) -- 设置通道音量，相对于主通道音量缩放`

### audio.setMinVolume()

`audio.setMinVolume()`函数将最小音量限制在设定的值上。任何低于最小音量的音量将以最小音量级别播放。

语法是 `audio.setMinVolume( volume, options )`。

参数如下：

+   `volume`：这允许你设置想要应用的新最小音量级别。有效的数字范围从 0.0 到 1.0，其中 1.0 是最大音量值。

+   `options`：这是一个支持你想要设置最小音量的单一关键字通道号的表。1 到最小通道数是有效的通道。指定 0 以将最小音量应用到所有通道。

示例如下：

```kt
audio.setMinVolume( 0.10, { channel=1 } ) -- set the min volume on channel 1
```

### audio.setMaxVolume()

`audio.setMaxVolume()`函数将最大音量限制在设定的值上。任何超过最大音量的音量将以最大音量级别播放。

语法是 `audio.setMaxVolume( volume, options )`。

参数如下：

+   `volume`：这允许你设置想要应用的新最大音量级别。有效的数字范围从 0.0 到 1.0，其中 1.0 是最大值。

+   `options`：这是一个支持单个键为你要设置最大音量的通道号的表。1 到最大通道数都是有效的通道。指定 0 将把最大音量应用到所有通道。

示例如下：

```kt
audio.setMaxVolume( 0.9, { channel=1 } ) -- set the max volume on channel 1
```

### audio.getVolume()

`audio.getVolume()`函数可以获取特定通道或主音量的音量。

语法为 `audio.getVolume( { channel=c } )`。

参数如下：

+   `channel`：设置你想要获取音量的通道号。有效的通道号最多可以有 32 个。指定 0 将返回所有通道的平均音量。完全省略此参数将获取主音量，这与通道音量不同。

以下是一些示例：

+   `masterVolume = audio.getVolume() -- 获取主音量`

+   `channel1Volume = audio.getVolume( { channel=1 } ) -- 获取通道 1 的音量`

### audio.getMinVolume()

`audio.getMinVolume()`函数可以获取特定通道的最小音量。

语法为 `audio.getMinVolume( { channel=c } )`。

参数如下：

+   `channel`：设置你想要获取最小音量的通道号。有效的通道号最多可以有 32 个。指定 0 将返回所有通道的平均最小音量。

示例如下：

```kt
channel1MinVolume = audio.getMinVolume( { channel=1 } ) -- get the min volume on channel 1
```

### audio.getMaxVolume()

`audio.getMaxVolume()`函数可以获取特定通道的最大音量。

语法为 `audio.getMaxVolume( { channel=c } )`。

参数如下：

+   `channel`：设置你想要获取最大音量的通道号。有效的通道号最多可以有 32 个。指定 0 将返回所有通道的平均音量。

示例如下：

```kt
channel1MaxVolume = audio.getMaxVolume( { channel=1 } ) -- get the max volume on channel 1
```

## 淡入淡出音频

你可以在任何音频开始播放时淡入音量，但也有其他控制方法。

### audio.fade()

`audio.fade()`函数会在指定的时间内将播放中的声音淡入到指定的音量。淡出完成后，音频将继续播放。

语法为 `audio.fade( [ { [channel=c] [, time=t] [, volume=v] } ] )`。

参数如下：

+   `channel`：设置你想要淡入的通道号。1 到最大通道数都是有效的通道。指定 0 将把淡入应用到所有通道。

+   `time`：设置从现在开始，你希望音频淡出并停止的时间量。省略此参数将调用默认的淡出时间，即 1,000 毫秒。

+   `volume`：设置你想要改变淡入的目标音量。有效的数值为 0.0 到 1.0，其中 1.0 是最大音量。如果省略此参数，默认值为 0.0。

请看以下示例：

```kt
audio.fade({ channel=1, time=3000, volume=0.5 } )
```

### audio.fadeOut()

`audio.fadeOut()`函数会在指定的时间内停止播放声音，并淡出到最小音量。在时间结束时音频将停止，通道将被释放。

语法为 `audio.fadeOut( [ { [channel=c] [, time=t] } ] )`。

参数如下：

+   `channel`：设置你要淡出的通道号。1 到最大通道数都是有效的通道。指定 0 以对所有通道应用淡出。

+   `time`：此参数设置从现在开始音频淡出并停止的时间长度。省略此参数将调用默认的淡出时间，即 1,000 毫秒。

示例如下：

```kt
audio.fadeOut({ channel=1, time=5000 } )
```

# 性能提示

在为你的游戏创建高质量音频时，可以参考这里提到的有用说明。

## 预加载阶段

最好在应用程序启动时预加载你经常使用的文件。虽然`loadStream()`通常很快，但`loadSound()`可能需要一段时间，因为它必须在需要时立即加载并解码整个文件。通常，你不想在应用程序需要流畅运行事件的部分调用`loadSound()`，比如在游戏玩法中。

## audioPlayFrequency

在`config.lua`文件中，你可以指定一个名为`audioPlayFrequency`的字段：

```kt
application =
{
  content =
  {
    width = 480,
    height = 960,
    scale = "letterbox",
    audioPlayFrequency = 22050
  },
}
```

这告诉 OpenAL 系统应以什么采样率进行混音和播放。为了获得最佳效果，此设置不应高于实际需求。例如，如果你不需要超过 22,050 Hz 的播放质量，就将其设置为 22,050。这样可以产生高质量的语音录音或中等质量的乐曲录音。如果你确实需要高音质，那么将其设置为 44,100 以在播放时产生类似音频 CD 的质量。

当你设置了此参数时，最好将所有音频文件编码为相同的频率。支持的值有 11,025、22,050 和 44,100。

## 专利和版税

对于高度压缩的格式，如 MP3 和 AAC，AAC 是更好的选择。AAC 是 MPEG 集团官方指定的 MP3 的继承者。如果你分发任何东西，可能需要关心 MP3 的专利和版税问题。你可能需要咨询律师以获得指导。当 AAC 被批准时，同意分发时不需要版税。如果你偏好使用 AAC 而非 MP3，这里有一个关于如何将 MP3 转换为 AAC 或你喜欢的任何文件格式的教程，可以在[`support.apple.com/kb/ht1550`](http://support.apple.com/kb/ht1550)查看。

Ogg Vorbis 是一种无版税和无专利的格式。然而，这种格式在 iOS 设备上不支持。

### 注意

关于音频格式的更多信息可以在[`www.nch.com.au/acm/formats.html`](http://www.nch.com.au/acm/formats.html)找到。移动开发者 Ray Wenderlich 也有一篇关于音频文件和数据格式的教程，可以在[`www.raywenderlich.com/204/audio-101-for-iphone-developers-file-and-data-formats`](http://www.raywenderlich.com/204/audio-101-for-iphone-developers-file-and-data-formats)查看。

## 音频小测验

Q1. 清除内存中音频文件的正确方法是什么？

1.  `audio.pause()`

1.  `audio.stop()`

1.  `audio.dispose()`

1.  `audio.fadeOut()`

Q2. 应用程序中可以同时播放多少个音频通道？

1.  10

1.  18

1.  25

1.  32

Q3. 你如何使音频文件无限循环？

1.  `loops = -1`

1.  `loops = 0`

1.  `loops = 1`

1.  以上都不对

# 总结

现在你已经了解了在 Corona SDK 中使用音频文件的重要方面。现在，你可以开始为你的游戏添加自己的声音效果和音乐，甚至可以添加到之前章节中你制作的任何示例中。这样做，你将为用户增加另一部分体验，这将吸引玩家进入你创造的环境。

到目前为止，你已经学会了如何：

+   使用`loadSound()`和`loadStream()`预加载和播放声音效果及音乐

+   在音频系统 API 下控制暂停、恢复、停止和倒带音乐轨道的音频功能

+   当音频不再使用时，从内存中释放

+   调整音频文件中的音量

在下一章中，你将结合到目前为止所学的所有内容来创建本书中的最终游戏。你还将学习目前市场上流行的移动游戏中实现物理对象和碰撞机制的其他方法。更多令人兴奋的学习内容在等着你。让我们加油！


# 第七章：物理现象——下落物体

> *关于如何使用显示对象整合物理引擎，有许多不同的方法。到目前为止，我们已经研究了移除碰撞物体、通过舞台区域移动物体以及通过施加力对抗重力来发射物体等方法，仅举几例。现在，我们将探索另一种允许重力控制环境的机制。我们接下来要创建的游戏涉及下落的物理物体。*

在本章中，我们将：

+   与更多物理实体合作

+   定制身体构建

+   跟踪被捕捉的物体

+   处理碰撞后的事件

+   创建下落的物体

在这一章中，让我们再创建一个有趣简单的游戏。开始行动吧！

# 创建我们的新游戏——蛋落

迄今为止的每一步都教会了我们更多关于 iOS/Android 设备上的游戏开发知识。在这个新的环节中，我们的游戏将包含音效，这将增强游戏中的感官体验。

### 提示

确保你使用的是 Corona SDK 的最新稳定版本。

我们将要创建的新游戏叫做蛋落。玩家控制主角，一个拿着平底锅的伐木工。在游戏过程中，蛋从天空中开始下落，伐木工的工作是用他的平底锅接住鸡蛋，不让它们掉到地上。每个被接住的蛋可以获得 500 分。玩家开始时有三个生命值。当一个蛋没有击中平底锅而是掉到地上时，就会失去一个生命值。当所有三个生命值都失去时，游戏结束。

在开始新的游戏项目时，请确保从`Chapter 7`文件夹中获取`Egg` `Drop`文件。你可以从 Packt Publishing 网站[`www.packtpub.com/`](http://www.packtpub.com/)下载本书附带的工程文件。其中包含了为你构建的所有必要文件，比如`build.settings`、`config.lua`、音频文件以及游戏所需的艺术资源。然后你需要在项目文件夹中创建一个新的`main.lua`文件，再开始编码。

![创建我们的新游戏——蛋落](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_07_01.jpg)

## 初始变量

这将是我们第一个完整的游戏设置，其中充满了显著的 Corona SDK 特性。我们将把我们迄今为止学到的关于变量、显示对象、物理引擎、触摸/加速度计事件和音频的基础知识结合起来。Corona 的许多 API 都易于使用和理解。这表明即使只有基本的编程知识甚至没有编程知识，也能快速学习 Corona。

# 动手操作——设置变量

让我们开始介绍我们将要用来创建游戏的变量。将会有显示对象和整数的组合来进行计数；我们还需要预加载游戏过程中使用的主要音效。按照步骤声明所有必需的变量：

1.  隐藏状态栏并在`display.newGroup()`组中添加名为`gameGroup`的组：

    ```kt
        display.setStatusBar( display.HiddenStatusBar )
        local gameGroup = display.newGroup()
    ```

1.  在游戏中包含外部模块：

    ```kt
        local physics = require "physics"
    ```

1.  添加显示对象：

    ```kt
        local background
        local ground
        local charObject
        local friedEgg
        local scoreText
        local eggText
        local livesText
        local shade
        local gameOverScreen
    ```

1.  添加变量：

    ```kt
        local gameIsActive = false
        local startDrop -- Timer object
        local gameLives = 3
        local gameScore = 0
        local eggCount = 0
        local mRand = math.random
    ```

1.  创建鸡蛋的边界和密度：

    ```kt
        local eggDensity = 1.0
        local eggShape = { -12,-13, 12,-13, 12,13, -12,13 }
        local panShape = { 15,-13, 65,-13, 65,13, 15,13 }
    ```

1.  设置加速度计和音频：

    ```kt
        system.setAccelerometerInterval( 100 )
        local eggCaughtSound = audio.loadSound( "friedEgg.wav" )
        local gameOverSound = audio.loadSound( "gameOver.wav" )
    ```

## *刚才发生了什么？*

我们继续创建类似于 Panda Star Catcher 游戏中变量的设置。通过将它们按组别、显示对象、音频等分类组织，效率会更高。

展示的许多变量都有指定的整数，以满足游戏玩法的目标。这包括像`gameLives` `=` `3`和`eggCount` `=` `0`这样的值。

## 控制主角

加速度计事件最好在游戏的主要范围内工作。它使你能够查看游戏环境的全部，而不必与屏幕上的触摸交互。必要的触摸事件对于像暂停、菜单、播放等用户界面按钮来说是有意义的。

# 动手时间——移动角色

鸡蛋将从天空的不同区域掉落到屏幕上。让我们准备让主角移动到屏幕上所有潜在的区域：

1.  创建一个名为`moveChar()`的新本地函数，并带有`event`参数：

    ```kt
    local moveChar = function(event)
    ```

1.  为角色添加加速度计移动：

    ```kt
      charObject.x = display.contentCenterX - (display.contentCenterX* (event.yGravity*3))
    ```

1.  创建角色在屏幕上移动的边界。这使得角色能够保持在游戏屏幕内，不会超出屏幕外的边界：

    ```kt
      if((charObject.x - charObject.width * 0.5) < 0) then charObject.x = charObject.width * 0.5
      elseif((charObject.x + charObject.width * 0.5) > display.contentWidth) then
      charObject.x = display.contentWidth - charObject.width * 0.5
      end
    end
    ```

## *刚才发生了什么？*

为了让加速度计移动与设备一起工作，我们必须使用`yGravity`。

### 注意

当相应地使用`xGravity`和`yGravity`时，加速度计事件基于竖屏比例。当显示对象被指定为横屏模式时，`xGravity`和`yGravity`的值会交换，以补偿事件正常工作。

注意，在第 3 步的代码中，防止了`charObject`显示对象越过任何墙边界。

## 动手英雄——添加触摸事件

角色目前由加速度计控制。控制角色的另一个选项是通过触摸事件。尝试将事件监听器替换为`"touch"`，并使用事件参数，以便触摸事件正常工作。

如果你记得我们在第三章，*打造我们的第一款游戏 – Breakout*和第四章，*游戏控制*中是如何将挡板移动与 Breakout 游戏结合在一起的，对于模拟器来说，这个过程应该非常相似。

## 更新得分

当更新得分时，它会引用我们的文本显示对象，并将数值转换为字符串。

这是一个示例：

```kt
gameScore = 100
scoreText = display.newText( "Score: " .. gameScore, 0, 0, "Arial", 45 )
scoreText:setTextColor( 1, 1, 1)
scoreText.x = 160; scoreText.y = 100
```

在上一个示例中，你会注意到我们将值`100`设置给了`gameScore`。在接下来的`scoreText`行中，使用了`gameScore`来连接"`Score:` "字符串和`gameScore`的值。这样做可以通过`scoreText`以字符串格式显示`gameScore`的值。

# 动手时间——设置得分

谁不喜欢友好的竞争呢？我们对前面章节中制作的游戏的计分板很熟悉。因此，我们对跟踪得分并不陌生。执行以下步骤来设置得分：

1.  创建一个名为`setScore()`的局部函数，它有一个名为`scoreNum`的参数：

    ```kt
        local setScore = function( scoreNum )
    ```

1.  设置变量以计算得分：

    ```kt
          local newScore = scoreNum
          gameScore = newScore
          if gameScore < 0 then gameScore = 0; end
    ```

1.  当在游戏玩法中获得分数时更新得分，并关闭函数：

    ```kt
          scoreText.text = "Score: " .. gameScore
          scoreText.xScale = 0.5; scoreText.yScale = 0.5
          scoreText.x = (scoreText.contentWidth * 0.5) + 15
          scoreText.y = 15
        end
    ```

## *刚才发生了什么？*

当在任何函数内调用`setScore(scoreNum)`时，它将引用使用`gameScore`变量的所有方法。假设在应用程序开始时`gameScore` `=` `0`，则该值会增加到`gameScore`设置的数量。

在`scoreText.text` `=` `"Score: " .. gameScore`中，`"Score: "`是在游戏过程中在设备上显示的字符串。`gameScore`变量获取赋予变量的当前值并将其显示为字符串。

## 显示游戏环境

为显示对象设置逻辑环境可以帮助玩家想象主角与环境之间的关系。由于我们的主角是伐木工人，将他在一个森林或完全专注于自然的环境中设置是有意义的。

# 动手操作——绘制背景

在本节中，我们将屏幕用环境显示对象填充。这包括我们的背景和地面对象，我们还可以为地面添加物理元素，以便我们可以为其指定碰撞事件。要绘制背景，请执行以下步骤：

1.  创建一个名为`drawBackground()`的局部函数：

    ```kt
        local drawBackground = function()
    ```

1.  添加背景图像：

    ```kt
          background = display.newImageRect( "bg.png", 480, 320 )
          background.x = 240; background.y = 160
          gameGroup:insert( background )
    ```

1.  添加地面元素并创建地面物理边界。关闭函数：

    ```kt
          ground = display.newImageRect( "grass.png", 480, 75 )
          ground.x = 240; ground.y = 325
          ground.myName = "ground"
          local groundShape = { -285,-18, 285,-18, 285,18, -285,18}
          physics.addBody( ground, "static", { density=1.0, bounce=0, friction=0.5, shape=groundShape } )
          gameGroup:insert( ground )
        end
    ```

## *刚才发生了什么？*

`background`和`ground`显示对象被放置在名为`drawBackground()`的函数中。由于我们对一些图像进行了动态缩放，因此使用了`display.newImageRect()`函数。地面显示对象有一个自定义的物理形状，其大小与原始显示对象不同。

我们的`background`对象被居中到设备屏幕区域的尺寸中，并插入到`gameGroup`。

`ground`显示对象被放置在显示区域的底部附近。通过`ground.myName` `=` `"ground"`为其分配一个名称。我们将在后面使用名称`"ground"`来确定碰撞事件。通过`groundShape`为地面创建了一个自定义的物理边界。这使得地面的主体可以影响显示对象的指定尺寸。当初始化`physics.addBody()`时，我们使用了`groundShape`作为形状参数。接下来，将`ground`也设置为`gameGroup`。

## 显示抬头显示器

在游戏中，**抬头显示**（**HUD**）是用于视觉上向玩家传递信息的方法。在许多游戏中，常见的信息包括健康/生命值、时间、武器、菜单、地图等。这使玩家在游戏过程中对当前发生的事情保持警惕。在跟踪生命值时，你希望知道在角色用完继续游戏的机会之前还剩下多少生命值。

# 行动时间——设计 HUD

尽管我们希望玩家的游戏体验愉快，但显示的信息必须与游戏相关，并且要策略性地放置，以免干扰主要游戏区域。因此，在设计 HUD 时，请执行以下步骤：

1.  创建一个名为 `hud()` 的新本地函数：

    ```kt
        local hud = function()
    ```

1.  显示在游戏过程中捕获的鸡蛋的文本：

    ```kt
          eggText = display.newText( "Caught: " .. eggCount, 0, 0, "Arial", 45 )
          eggText:setTextColor( 1, 1, 1 )
          eggText.xScale = 0.5; eggText.yScale = 0.5
          eggText.x = (480 - (eggText.contentWidth * 0.5)) - 15
          eggText.y = 305
          gameGroup:insert( eggText )
    ```

1.  添加跟踪生命值的文本：

    ```kt
          livesText = display.newText( "Lives: " .. gameLives, 0, 0, "Arial", 45 )
          livesText:setTextColor( 1, 1, 1 )--> white
          livesText.xScale = 0.5; livesText.yScale = 0.5  --> for clear retina display text
          livesText.x = (480 - (livesText.contentWidth * 0.5)) - 15
          livesText.y = 15
          gameGroup:insert( livesText )
    ```

1.  添加分数的文本并关闭函数：

    ```kt
          scoreText = display.newText( "Score: " .. gameScore, 0, 0, "Arial", 45 )
          scoreText:setTextColor( 1, 1, 1 )--> white
          scoreText.xScale = 0.5; scoreText.yScale = 0.5  --> for clear retina display text
          scoreText.x = (scoreText.contentWidth * 0.5) + 15
          scoreText.y = 15
          gameGroup:insert( scoreText )
        end
    ```

    ![行动时间——设计 HUD](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_07_02.jpg)

## *刚才发生了什么？*

`eggText` 显示对象可以在屏幕的右下角找到。它在游戏过程中对用户仍然可见，同时又不占据主要焦点。注意 `eggText = display.newText( "Caught: " .. eggCount, 0, 0, "Arial", 45 )` 将在值更新时引用 `eggCount`。

`livesText` 显示对象的设置与 `eggText` 类似。它被放置在屏幕的右上角附近。由于这个对象在游戏中非常重要，它的位置相当突出。它位于一个可以从背景中注意到并且在游戏中可以参考的区域。当 `gameLives` 更新时，`livesText` 显示对象会减少数字。

`scoreText` 的初始设置在 `hud()` 函数中开始。它被放置在屏幕的左上角，与 `livesText` 相对。

## 创建游戏生命值

如果游戏中没有后果，那么完成主要目标就没有紧迫感。为了保持玩家在游戏中的参与度，引入一些具有挑战性的元素将保持竞争性和兴奋感。在游戏中添加后果为玩家创造紧张感，并给他们更多保持生存的动力。

# 行动时间——计算生命值

跟踪游戏中的剩余生命值，让玩家了解游戏结束还有多久。为了计算游戏中剩余的生命值，请执行以下步骤：

1.  设置一个名为 `livesCount()` 的函数：

    ```kt
        local livesCount = function()
    ```

1.  每次生命值减少时，显示生命值的文本：

    ```kt
          gameLives = gameLives - 1
          livesText.text = "Lives: " .. gameLives
          livesText.xScale = 0.5; livesText.yScale = 0.5  --> for clear retina display text
          livesText.x = (480 - (livesText.contentWidth * 0.5)) - 15
          livesText.y = 15
          print(gameLives .. " eggs left")
          if gameLives < 1 then
            callGameOver()
          end
        end
    ```

## *刚才发生了什么？*

`livesCount()`函数是一个单独的函数，用于更新`gameLives`。它确保你注意到`gameLives = gameLives – 1`。这减少了代码开始时实例化的设定值。当`gameLives`的值发生变化时，它通过`livesText`显示更新。在函数末尾使用`print`语句，在终端窗口中跟踪计数。

当`gameLives < 1`时，将调用`callGameOver()`函数，并显示游戏结束元素。

## 动手试试看——为游戏生命值添加图像

目前，游戏在屏幕上使用显示文本来显示游戏进行期间还剩下多少生命值。使 HUD 显示更具吸引力的方法之一是创建/添加与游戏相关的小图标，例如鸡蛋或煎锅。

需要创建三个独立的显示对象，并有序地放置，以便当生命值被扣除时，对象的透明度降低到 0.5。

需要创建一个方法，以便当游戏生命值降至零时，所有三个显示对象都会受到影响。

## 介绍主角

我们的主角将在游戏过程中对每个应用的动作进行动画处理。我们还将创建一个复杂的身体构造，因为其碰撞点的焦点将放在角色持有的物体上，而不是整个身体。

### 复杂身体构造

也可以从多个元素构建身体。每个身体元素都是一个单独的多边形形状，具有自己的物理属性。

由于 Box2D 中的碰撞多边形必须是凸面，因此任何具有凹形状的游戏对象都必须通过附加多个身体元素来构建。

复杂身体的构造函数与简单多边形身体的构造函数相同，不同之处在于它有不止一个身体元素列表：

```kt
physics.addBody( displayObject, [bodyType,] bodyElement1, [bodyElement2, ...] )
```

每个身体元素可能都有自己的物理属性，以及其碰撞边界的形状定义。以下是一个示例：

```kt
local hexagon = display.newImage("hexagon.png")
hexagon.x = hexagon.contentWidth
hexagon.y = hexagon.contentHeight
hexagonShape = { -20,-40, 20, -40, 40, 0, 20,40, -20,40, -40,0 }
physics.addBody( hexagon, "static", { density = 1.0, friction = 0.8, bounce = 0.3, shape=hexagonShape } )
```

与更简单的情况一样，`bodyType`属性是可选的，如果没有指定，将默认为`"dynamic"`。

# 动手操作——创建角色

主角是用一个精灵表创建的，需要设置以查看它提供的动画。其他将出现的显示图像包括当与物理对象发生碰撞时出现的破裂鸡蛋。要创建角色，请执行以下步骤：

1.  创建一个名为`createChar()`的新局部函数：

    ```kt
        local createChar = function()
    ```

1.  为主角创建精灵表：

    ```kt
    local sheetData = { width=128, height=128, numFrames=4, sheetContentWidth=256, sheetContentHeight=256 }
    local sheet = graphics.newImageSheet( "charSprite.png", sheetData )

        local sequenceData = 
        {
          { name="move", start=1, count=4, time=400 } 
        }

        charObject = display.newSprite( sheet, sequenceData )
        charObject:setSequence("move")
        charObject:play()
    ```

1.  设置主角的起始位置和物理属性：

    ```kt
        charObject.x = 240; charObject.y = 250
        physics.addBody( charObject, "static", { density=1.0, bounce=0.4, friction=0.15, shape=panShape } )
        charObject.rotation = 0
        charObject.isHit = false -- When object is not hit
        charObject.myName = "character"
    ```

1.  在鸡蛋发生碰撞后添加过渡图像：

    ```kt
        friedEgg = display.newImageRect( "friedEgg.png", 40, 23 )
        friedEgg.alpha = 1.0
        friedEgg.isVisible = false
        gameGroup:insert( charObject )
        gameGroup:insert( friedEgg )
      end
    ```

    ![动手操作——创建角色](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_07_03.jpg)

## *刚才发生了什么？*

所引用的图像集被称为`sheetData`，它从`"charSprite.png"`中获取前`4`帧动画。我们创建了一个名为`"move"`的动画集。每次调用`"move"`时，都会从第`1`帧开始播放，每`400`毫秒播放从开始的前`4`帧。

主显示对象称为`charObject`，它具有`sheetData`的特征。当它调用`setSequence("move")`时，执行`play()`命令时会播放该动画序列。

对角色物理身体的一个重要更改是，它的主要碰撞点将指向动画中使用的煎锅。角色身体上的任何碰撞检测都不会被读取。`charObject`显示对象被赋予一个名为`"character"`的名字，这将用于检测与掉落鸡蛋的碰撞。

我们还在这个函数中放置了煎蛋，为碰撞做准备。

## 添加后碰撞

我们要确保当一个对象与另一个对象交互后，紧接着就会发生一个事件类型。在碰撞后的瞬间，我们可以确认两个对象之间的碰撞力。这有助于我们确定被销毁的对象是受到一定力量的完全撞击。

### 碰撞处理

请注意您处理 Box2D 物理引擎的方式。如果 Corona 代码在碰撞过程中尝试修改仍在碰撞中的对象，Box2D 将会崩溃，因为 Box2D 仍在对它们进行迭代数学计算。

为了防止碰撞检测时立即发生崩溃，不要让碰撞立即发生。

在碰撞过程中，请勿修改/创建/销毁物理对象，以防止程序崩溃。

如果您需要在碰撞后修改/创建/销毁一个对象，您的碰撞处理程序应设置一个标志或添加一个时间延迟，以便稍后使用`timer.performWithDelay()`进行更改。

## 刚体属性

许多原生的 Box2D 方法已经被简化为显示对象的点属性。以下示例显示，一个名为`newBody`的刚体是使用其中一个构造方法创建的。

### body.isAwake

这是一个表示当前唤醒状态的布尔值。默认情况下，当所有刚体在几秒钟内没有交互时，它们会自动*进入* *休眠*状态。刚体停止模拟，直到某种碰撞或其他交互唤醒它们。

这是一个示例：

```kt
newBody.isAwake = true
local object = newBody.isAwake
```

### body.isBodyActive

这是一个表示刚体激活状态的布尔值。非激活状态的刚体不会被销毁，但它们会从模拟中移除，并停止与其他刚体的交互。

这是一个示例：

```kt
newBody.isBodyActive = true
local object = newBody.isBodyActive
```

### body.isBullet

这是一个将刚体视为*子弹*的布尔值。子弹将受到连续碰撞检测。默认值为`false`。

这是一个示例：

```kt
newBody.isBullet = true
local object = newBody.isBullet
```

### body.isSensor

这是一个布尔属性，用于设置整个物体中的`isSensor`属性。传感器可以穿过其他物体而不是反弹，但能检测到一些碰撞。这个属性作用于所有物体元素，并将覆盖元素本身的任何`isSensor`设置。

这是一个示例：

```kt
newBody.isSensor = true
```

### body.isSleepingAllowed

这是一个布尔值，用于设置一个物体是否允许进入休眠状态。醒着的物体在比如倾斜重力的情况下很有用，因为休眠的物体不会对全球重力变化做出反应。默认值为`true`。

这是一个示例：

```kt
newBody.isSleepingAllowed = true
local object = newBody.isSleepingAllowed
```

### body.isFixedRotation

这是一个布尔值，用于设置一个物体的旋转是否应该被锁定，即使物体即将加载或受到偏心力的作用。默认值为`false`。

这是一个示例：

```kt
newBody.isFixedRotation = true
local object = newBody.isFixedRotation
```

### body.angularVelocity

这是当前旋转速度的值，单位为每秒度数。

这是一个示例：

```kt
newBody.angularVelocity = 50
local myVelocity = newBody.angularVelocity
```

### body.linearDamping

这是用于控制物体线性运动阻尼的值。这是角速度随时间减少的速率。默认值为零。

这是一个示例：

```kt
newBody.linearDamping = 5
local object = newBody.linearDamping
```

### body.angularDamping

这是用于控制物体旋转阻尼的值。默认值为零。

这是一个示例：

```kt
newBody.angularDamping = 5
local object = newBody.angularDamping
```

### body.bodyType

这是一个字符串值，用于设置模拟的物理物体的类型。可用的值有`"static"`、`"dynamic"`和`"kinematic"`，具体解释如下：

+   `static`（静止）物体不会移动也不会相互影响。静止物体的例子包括地面或迷宫的墙壁。

+   `dynamic`（动态）物体受重力影响，也会与其他类型的物体发生碰撞。

+   `kinematic`（运动学）物体受力影响但不受重力影响。那些可拖动的物体在拖动事件期间应该被设置为`"kinematic"`。

默认的物体类型是`"dynamic"`。

这是一个示例：

```kt
newBody.bodyType = "kinematic"
local currentBodyType = newBody.bodyType
```

# 行动时间——创建鸡蛋碰撞

在我们之前创建的示例游戏中已经处理过碰撞。处理碰撞后的事件需要引入力来完成碰撞后的动作：

1.  创建一个名为`onEggCollision()`的新局部函数，它有两个参数，分别名为`self`和`event`：

    ```kt
        local onEggCollision = function( self, event )
    ```

1.  当力大于`1`时创建一个`if`语句，并包含`not` `self.isHit`。加入`eggCaughtSound`音效：

    ```kt
          if event.force > 1 and not self.isHit then
            audio.play( eggCaughtSound )
    ```

1.  使`self`变得不可见且不活跃，并用`friedEgg`显示对象替换它：

    ```kt
            self.isHit = true
            print( "Egg destroyed!")
            self.isVisible = false
            friedEgg.x = self.x; friedEgg.y = self.y
            friedEgg.alpha = 0
            friedEgg.isVisible = true
    ```

1.  创建一个函数，通过使用`onComplete`命令将`friedEgg`显示对象过渡并使其在舞台上淡出：

    ```kt
            local fadeEgg = function()
              transition.to( friedEgg, { time=500, alpha=0 } )
            end
            transition.to( friedEgg, { time=50, alpha=1.0, onComplete=fadeEgg } )
            self.parent:remove( self )
            self = nil
    ```

1.  使用`if event.other.myName == "character"`，当主角接住鸡蛋时更新`eggCount`。并且，每次碰撞增加`gameScore` `500`分。如果鸡蛋掉到地上，使用`elseif event.other.myName == "ground"`并通过`livesCount()`减少生命值：

    ```kt
            if event.other.myName == "character" then
              eggCount = eggCount + 1
              eggText.text = "Caught: " .. eggCount
              eggText.xScale = 0.5; eggText.yScale = 0.5  --> for clear retina display text
              eggText.x = (480 - (eggText.contentWidth * 0.5)) - 15
              eggText.y = 305
              print("egg caught")
              local newScore = gameScore + 500
              setScore( newScore )
            elseif event.other.myName == "ground" then
              livesCount()
              print("ground hit")
            end
          end
        end
    ```

    ![行动时间——创建鸡蛋碰撞](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_07_04.jpg)

## *刚才发生了什么？*

使用 `onEggCollision( self, event )` 函数，我们通过 `if` 语句设置条件为 `event.force > 1` 且 `not self.isHit`。当两个语句都返回 `true` 时，播放鸡蛋的声音效果。碰撞发生后，从天空中落下的初始鸡蛋从场景中移除，并在同一位置使用 `friedEgg` 显示对象替换，通过 `friedEgg.x = self.x; friedEgg.y = self.y` 实现。

`fadeEgg()` 函数通过 `transition.to( eggCrack, { time=50, alpha=1.0, onComplete=fadeCrack } )` 在 `50` 毫秒内使新替换的鸡蛋对象出现，然后通过 `onComplete` 命令，使用 `transition.to( eggCrack, { time=500, alpha=0 } )` 将对象返回到不可见状态。

当从 `event.other.myName` 调用 `"character"` 名称时，分配给该名称的每次碰撞都会使 `eggCount + 1`。因此，`eggText` 使用 `eggCount` 的值进行更新。`setScore( newScore )` 语句在每次与 `"character"` 发生碰撞时将分数增加 `500`。当与 `"ground"` 发生碰撞时，调用 `livesCount()` 函数，该函数将生命值减去 `1`。

## 使显示对象下落

我们将通过学习如何将物理对象添加到场景中，并让它们在游戏中的随机区域下落，来应用主要资源（鸡蛋对象）。物理引擎将考虑我们为鸡蛋显示对象创建的动态物理体。

# 行动时间——添加鸡蛋对象

想象一个充满下落鸡蛋的世界。这并不完全现实，但在这个游戏中，我们将创建这个元素。至少，我们将确保重力和现实世界物理被应用。要添加鸡蛋对象，请执行以下步骤：

1.  创建一个名为 `eggDrop()` 的新本地函数：

    ```kt
        local eggDrop = function()
    ```

1.  添加 `egg` 显示对象的属性：

    ```kt
          local egg = display.newImageRect( "egg.png", 26, 30 )
          egg.x = 240 + mRand( 120 ); egg.y = -100
          egg.isHit = false
          physics.addBody( egg, "dynamic",{ density=eggDensity, bounce=0, friction=0.5, shape=eggShape } )
          egg.isFixedRotation = true
          gameGroup:insert( egg )
    ```

1.  为 `egg` 显示对象添加 `postCollision` 事件：

    ```kt
          egg.postCollision = onEggCollision
          egg:addEventListener( "postCollision", egg )
        end
    ```

    ![行动时间——添加鸡蛋对象](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_07_05.jpg)

## *刚才发生了什么？*

我们用 `240 + mRand( 120 )` 设置了 `egg` 的 `x` 值。`mRand` 函数等于 `math.random`，这将允许鸡蛋在从 *x* 方向的 50 开始的 `120` 像素区域内随机位置出现。

确保在碰撞事件正确应用时 `egg.isHit = false` 是至关重要的。物理体设置为 `"dynamic"` 以便它对重力作出反应并使对象下落。我们创建的鸡蛋有一个自定义的密度和形状，这在代码开始时就已经设置好了。

为了让碰撞生效，最后一个重要的细节是使用 `egg.postCollision = onEggCollision` 将 `egg` 对象添加到 `onEggCollision()` 函数中，然后让事件监听器通过 `egg:addEventListener( "postCollision", egg )` 使用 `"postCollision"` 事件。

# 行动时间——使鸡蛋降落

我们将执行鸡蛋的计时器，以便它们可以开始在屏幕上降落。要使鸡蛋降落，请执行以下步骤：

1.  创建一个名为`eggTimer()`的局部函数，并使用`timer.performWithDelay`每 1 秒（1000 毫秒）重复投放一个鸡蛋。使用`eggDrop()`来激活下落：

    ```kt
        local eggTimer = function()
          startDrop = timer.performWithDelay( 1000, eggDrop, 0 )
        end
    ```

1.  在`onEggCollision()`函数的第一个`if`语句内，使用`timerID`和`startDrop`变量取消计时器。然后添加`if gameLives < 1`语句以停止鸡蛋下落：

    ```kt
          if gameLives < 1 then
            timer.cancel( startDrop )
            print("timer cancelled")
          end
    ```

## *刚才发生了什么？*

为了让鸡蛋从天空中开始下落，我们创建了一个名为`eggTimer()`的函数。它通过`startDrop = timer.performWithDelay( 1000, eggDrop, 0 )`每隔 1000 毫秒（1 秒）无限次地激活`eggDrop()`函数，让一个鸡蛋下落。

回到`onEggCollision()`，我们要检查`gameLives`是否已经小于`1`。当这个语句为真时，鸡蛋将停止下落。这是通过`timer.cancel( startDrop )`实现的。我们在`eggTimer()`中设置的`timerID`就是`startDrop`。

## 结束游戏玩法

每个游戏的开始总有一个结局，无论是简单的*胜利*或*失败*，还是仅仅是一个*游戏结束*；所有这些都给玩家一个结束感。通知玩家这些事件很重要，这样他们才能反思所获得的成就。

# 行动时间——调用游戏结束

我们将确保当游戏结束显示屏幕弹出时，当前正在移动的任何显示对象停止移动，并且事件监听器被停用。除了我们的游戏结束屏幕的视觉显示外，我们还将添加一个声音通知，这将帮助触发事件。要结束游戏，请执行以下步骤：

1.  创建一个名为`callGameOver()`的新局部函数，并将其放在`setScore()`函数之后，`drawBackground()`函数之前：

    ```kt
        local callGameOver = function()
    ```

1.  当游戏结束显示弹窗时引入声音效果。将`gameIsActive`设置为`false`并在游戏中暂停物理效果：

    ```kt
          audio.play( gameOverSound )
          gameIsActive = false
          physics.pause()
    ```

1.  创建一个覆盖当前背景的阴影：

    ```kt
          shade = display.newRect( 0, 0, 570, 320 )
          shade:setFillColor( 0, 0, 0 )
          shade.x = 240; shade.y = 160
          shade.alpha = 0  -- Getting shade ready to display at game end
    ```

1.  显示游戏结束窗口并重申最终得分：

    ```kt
          gameOverScreen = display.newImageRect( "gameOver.png", 400, 300 )
          local newScore = gameScore
          setScore( newScore )
          gameOverScreen.x = 240; gameOverScreen.y = 160
          gameOverScreen.alpha = 0
          gameGroup:insert( shade )
          gameGroup:insert( gameOverScreen )
          transition.to( shade, { time=200, alpha=0.65 } )
          transition.to( gameOverScreen, { time=500, alpha=1 } )
    ```

1.  在游戏结束屏幕上显示得分：

    ```kt
          scoreText.isVisible = false
          scoreText.text = "Score: " .. gameScore
          scoreText.xScale = 0.5; scoreText.yScale = 0.5  --> for clear retina display text
          scoreText.x = 240
          scoreText.y = 160
          scoreText:toFront()  -- Moves to front of current display group
          timer.performWithDelay( 0,
            function() scoreText.isVisible = true; end, 1 )
        end
    ```

    ![行动时间——调用游戏结束](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_07_06.jpg)

## *刚才发生了什么？*

我们的`gameOver()`函数触发了我们在代码开始时预加载的`gameOverSound`声音效果。我们确保通过`gameIsActive = false`禁用任何事件，比如加速度计的运动。

在这个时候，我们的显示对象元素会出现在`shade`、`gameOverScreen`和`scoreText`中。

如果你注意到，当游戏玩法结束时，`scoreText`通过`scoreText.isVisible = false`消失，然后在屏幕的另一区域使用`timer.performWithDelay( 0, function() scoreText.isVisible = true; end, 1 )`重新出现。

## 开始游戏

我们将激活所有剩余的函数，并让它们相应地运行。

# 行动时间——激活游戏

所有游戏玩法元素设置好后，是时候通过以下步骤启动应用程序了：

1.  创建一个名为`gameActivate()`的新局部函数，并插入`gameIsActive = true`。将此函数放在`moveChar()`函数上方：

    ```kt
        local gameActivate = function()
          gameIsActive = true
        end
    ```

1.  通过创建一个名为`gameStart()`的新函数来初始化所有游戏动作：

    ```kt
        local gameStart = function()
    ```

1.  启动物理属性并为下落物体设置重力：

    ```kt
          physics.start( true )
          physics.setGravity( 0, 9.8 )
    ```

1.  激活所有实例化的函数。为`charObject`添加事件监听器，使用`"accelerometer"`事件监听`moveChar()`函数：

    ```kt
          drawBackground()
          createChar()
          eggTimer()
          hud()
          gameActivate()
          Runtime:addEventListener("accelerometer", moveChar)
        end
    ```

1.  实例化`gameStart()`函数并返回`gameGroup`组：

    ```kt
        gameStart()
        return gameGroup
    ```

## *刚才发生了什么？*

如果你记得，在我们的代码开始时，我们设置了`gameIsActive = false`。现在我们将通过`gameActivate()`函数改变这个状态，使`gameIsActive = true`。我们让`gameStart()`函数应用所有初始游戏元素。这包括物理引擎和重力的启动。同时，我们取所有函数的余数并初始化它们。

一旦所有函数被激活，需要返回`gameGroup`，以便在游戏进行时显示所有显示对象。

为了确保你的显示对象的物理对象边界位于正确位置，在`gameStart()`函数中使用`physics.setDrawMode( "hybrid" )`。

## 小测验 - 动画图形

问题 1. 什么可以检索或设置文本对象的文本字符串？

1.  `object.text`

1.  `object.size`

1.  `object:setTextColor()`

1.  以上都不是

问题 2. 什么函数将任何参数转换成字符串？

1.  `tonumber()`

1.  `print()`

1.  `tostring()`

1.  `nil`

问题 3. 哪种体型受到重力和与其他体型碰撞的影响？

1.  动态

1.  动力学

1.  静态

1.  以上都不是

# 总结

我们的应用程序的游戏玩法构建现在已完成。现在我们熟悉了使用物理引擎的各种方式，这表明使用 Box2D 设计涉及物理体的其他游戏是多么容易。

我们现在对以下内容有了更好的了解：

+   应用动态和静态物理体的使用

+   为我们的显示对象的物理属性构建自定义形状

+   使用给定变量的值跟踪捕获的对象数量

+   使用后碰撞来切换图像

在下一章中，我们将通过使用 Composer API 创建多功能菜单屏幕来完成游戏体验。你还将学习如何添加暂停动作，保存高分以及了解有关数据保存和卸载文件更多信息。

使用 Corona SDK 帮助我们以最少的时间设计和开发游戏。让我们继续为我们的游戏添加最后的润色！


# 第八章：操作编排器

> *我们已经将游戏 Egg Drop 进行了探索，创建了游戏物理以反应碰撞检测并跟踪其他有用的数据，如生命值和积分系统。我们还处理了自定义物理实体，并为我们的显示对象创建了名称，这些名称适用于游戏分数计数。*

接下来，我们将添加一个菜单系统，其中包括游戏介绍，游戏中应用暂停菜单，并在游戏结束时保存高分。

我们正在完成一个应用程序，它具备了发布到 App Store 和 Google Play Store 所需的必要元素。

在本章中，我们将：

+   保存和加载高分

+   添加暂停菜单

+   使用 Composer API 管理场景

+   添加加载屏幕

+   添加主菜单、选项菜单和制作人员屏幕

那么，让我们开始吧！

# 继续鸡蛋掉落游戏（Egg Drop）

我们已经完成了 Egg Drop 的主要游戏部分，作为我们应用程序的基础。现在，是时候让我们加入如何在游戏中途暂停动作以及保存高分的方法了。我们还将添加一些新场景，帮助我们轻松快速地介绍和过渡到游戏。

在`第八章`的`Resources`文件夹中，获取所有图像和文件资源，并将它们复制到当前的`Egg Drop`项目文件夹中。你可以从 Packt Publishing 网站下载伴随这本书的项目文件。我们将使用这些文件为我们的游戏添加最后的润色。

# 数据保存

保存文件信息在游戏开发的许多方面都有应用。我们用它来保存高分和游戏设置，如声音开关、锁定/解锁关卡等。这些功能并非必须，但既然它们很好，也许你希望在应用程序中包含它们。

在 Corona SDK 中，应用程序是沙盒化的；这意味着你的文件（应用程序图片、数据和个人偏好设置）存储在一个其他应用程序无法访问的位置。你的文件将驻留在特定于应用程序的目录中，用于文档、资源或临时文件。这个限制与你在 Mac 或 PC 上编程时的文件有关，而不是设备上的文件。

## BeebeGames 类用于保存和加载值

我们将使用由 Jonathan Beebe 创建的 BeebeGames 类。它提供了许多简单且实用的游戏功能。其中一些值得注意的功能包括一种简单保存和加载数据的方法，我们可以将其加入到我们的游戏中。关于 BeebeGames 类的更多文档可以在`第八章`文件夹中找到。

### 注意

你还可以参考[`github.com/lewisNotestine/luaCorona/blob/master/justATest/code/beebegames.lua`](https://github.com/lewisNotestine/luaCorona/blob/master/justATest/code/beebegames.lua)，以跟踪类的更新。

如果你想将来使用它们，可以查看其他与动画、过渡、定时器等相关的方法。现在，我们将专注于可以使用这些方法轻松地为我们的游戏保存和加载值。

下面是一个保存和加载值的示例：

```kt
-- Public Method: saveValue() --> save single-line file (replace contents)

function saveValue( strFilename, strValue )
  -- will save specified value to specified file
  local theFile = strFilename
  local theValue = strValue

  local path = system.pathForFile( theFile, system.DocumentsDirectory)

  -- io.open opens a file at path. returns nil if no file found
  -- "w+": update mode, all previous data is erased
  local file = io.open( path, "w+" )
  if file then
  -- write game score to the text file
  file:write( theValue )
  io.close( file )
  end
end

-- Public Method: loadValue() --> load single-line file and store it into variable

function loadValue( strFilename )
  -- will load specified file, or create new file if it doesn't exist

  local theFile = strFilename

  local path = system.pathForFile( theFile, system.DocumentsDirectory)

  -- io.open opens a file at path. returns nil if no file found
  -- "r": read mode
  local file = io.open( path, "r" )
  if file then
    -- read all contents of file into a string
    -- "*a": reads the whole file, starting at the current position
    local contents = file:read( "*a" )
    io.close( file )
    return contents
  else
    -- create file b/c it doesn't exist yet
    -- "w": write mode
    file = io.open( path, "w" )
    file:write( "0" )
    io.close( file )
    return "0"
  end
end
```

## 获取文件的路径

这些文件的路径对于你的应用程序来说是唯一的。要创建文件路径，你可以使用`system.pathForFile`函数。这个函数会生成一个绝对路径到应用程序的图标文件，以应用程序的资源目录作为`Icon.png`的基础目录：

```kt
local path = system.pathForFile( "Icon.png", system.ResourceDirectory)
```

通常，你的文件必须位于三个可能的基础目录之一：

+   `system.DocumentsDirectory`：这应该用于需要在应用程序会话之间持久存在的文件。

+   `system.TemporaryDirectory`：这是一个临时目录。写入这个目录的文件不能保证在后续的应用程序会话中存在。它们可能存在，也可能不存在。

+   `system.ResourceDirectory`：这是所有应用程序资源的目录。注意，你不应该在这个目录中创建、修改或添加文件。

### 注意

关于文件的更多信息可以在[`docs.coronalabs.com/api/library/system/index.html`](http://docs.coronalabs.com/api/library/system/index.html)找到。

## 读取文件

要读取文件，使用`io`库。这个库允许你管理文件，给定一个绝对路径。

## 写入文件

要写入文件，你可以按照很多与读取文件相同的步骤进行。不同的是，你不是使用读取方法，而是将数据（字符串或数字）写入文件。

# 是时候行动了——保存和加载最高分

当**游戏结束**屏幕显示时，我们将保存并加载最终得分和最高分值。为此，执行以下步骤：

1.  打开为 Egg Drop 创建的`main.lua`文件。我们将继续使用同一个文件，并添加更多代码以及对游戏的新的修改。

1.  在代码顶部，所有其他初始化变量的位置加入两个新的变量，`local highScoreText`和`local highScore`：

    ```kt
    local highScoreText
    local highScore
    ```

1.  在预加载的音频文件后引入`saveValue()`函数：

    ```kt
      local saveValue = function( strFilename, strValue )
        -- will save specified value to specified file
        local theFile = strFilename
        local theValue = strValue

        local path = system.pathForFile( theFile, system.DocumentsDirectory )

        -- io.open opens a file at path. returns nil if no file found
        local file = io.open( path, "w+" )
        if file then
          -- write game score to the text file
          file:write( theValue )
          io.close( file )
        end
      end
    ```

1.  加入`loadValue()`函数：

    ```kt
      local loadValue = function( strFilename )
        -- will load specified file, or create new file if it doesn't exist

        local theFile = strFilename

        local path = system.pathForFile( theFile, system.DocumentsDirectory )

        -- io.open opens a file at path. returns nil if no file found
        local file = io.open( path, "r" )
        if file then
          -- read all contents of file into a string
          local contents = file:read( "*a" )
          io.close( file )
          return contents
         else
          -- create file b/c it doesn't exist yet
          file = io.open( path, "w" )
          file:write( "0" )
          io.close( file )
           return "0"
        end
      end
    ```

1.  在`callGameOver()`函数的最后，创建一个`if`语句来比较`gameScore`和`highScore`。使用`saveValue()`函数保存最高分：

    ```kt
        if gameScore > highScore then
          highScore = gameScore
          local highScoreFilename = "highScore.data"
          saveValue( highScoreFilename, tostring(highScore) )
        end
    ```

1.  接下来，在同一个`callGameOver()`函数中加入`highScoreText`显示文本，以便在游戏结束时显示最高分：

    ```kt
        highScoreText = display.newText( "Best Game Score: " .. tostring( highScore ), 0, 0, "Arial", 30 )
        highScoreText:setTextColor( 1, 1, 1 )	
        highScoreText.xScale = 0.5; highScoreText.yScale = 0.5
        highScoreText.x = 240
        highScoreText.y = 120

        gameGroup:insert( highScoreText )
    ```

1.  在`gameStart()`函数的最后，使用`loadValue()`函数加载最高分：

    ```kt
          local highScoreFilename = "highScore.data"
          local loadedHighScore = loadValue( highScoreFilename )

          highScore = tonumber(loadedHighScore)
    ```

    ![是时候行动了——保存和加载最高分](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_08_01.jpg)

## *刚才发生了什么？*

在游戏级别初始化了`saveValue()`和`loadValue()`函数后，我们创建了一个`if`语句来比较`gameScore`（游戏进行时的当前得分）和`highScore`（迄今为止获得过的最高得分）。当`gameScore`的结果更高时，它就会替换保存的`highScore`数据。

为了保存这个值，需要创建一个数据文件。我们创建了一个名为`local highScoreFilename = "highscore.data"`的变量。我们使用`highScoreFilename`作为参数调用了`saveValue()`函数。`tostring(highScore)`参数会将`highScore`的数值转换为字符串。

当**游戏结束**屏幕可见时，`highScoreText`会显示从`highScore`保存的值，位于达到的`gameScore`上方。添加高分可以激励玩家争取最高分，并增加游戏的重复可玩性。

在`gameStart()`函数中，重要的是要在游戏开始时加载`highScore.data`的值。使用我们创建的用来保存`highScore`的同一个数据文件，我们也可以在游戏中加载这个值。为了加载这个值，`local highScore`调用`loadValue(highScoreFileName)`。这会从`highScore.data`获取信息。为了得到这个值，`tonumber(loadedHighScore)`将其从字符串转换为整数，并可以用来显示`highScore`的值。

# 暂停游戏

你是否曾在玩游戏时突然需要去洗手间或者手抽筋？显然，这些情况都需要你暂时将注意力从游戏进度上转移，并且需要暂时停止当前动作来处理这些需求。这时暂停按钮就显得非常方便，这样你就可以在那一刻停止动作，并在准备好再次游戏时从停止的地方继续。

# 动作时间——暂停游戏

这不仅仅是制作一个按钮；还包括通过执行以下步骤暂停屏幕上的所有动作，包括物理效果和计时器：

1.  在代码开始部分初始化其他变量时，添加`local pauseBtn`和`local pauseBG`变量。在脚本顶部`gameOverSound`之后预加载`btnSound`音频：

    ```kt
    -- Place near other game variables
    local pauseBtn
    local pauseBG

    -- Place after gameOverSound
    local btnSound = audio.loadSound( "btnSound.wav" )
    ```

1.  在`hud()`函数内，在`scoreText`部分之后创建另一个函数，用于运行暂停按钮的事件。调用`onPauseTouch(event)`函数。通过将`gameIsActive`设置为`false`来暂停游戏中的物理效果，并让暂停元素在屏幕上显示：

    ```kt
        local onPauseTouch = function( event )
          if event.phase == "release" and pauseBtn.isActive then
            audio.play( btnSound )

            -- Pause the game

            if gameIsActive then

              gameIsActive = false
              physics.pause()

              local function pauseGame()
                timer.pause( startDrop )
                print("timer has been paused")
              end
              timer.performWithDelay(1, pauseGame)

              -- SHADE
              if not shade then
                shade = display.newRect( 0, 0, 570, 380 )
                shade:setFillColor( 0, 0, 0 )
                shade.x = 240; shade.y = 160
                gameGroup:insert( shade )
              end
              shade.alpha = 0.5

              -- SHOW MENU BUTTON
              if pauseBG then
                pauseBG.isVisible = true
                pauseBG.isActive = true
                pauseBG:toFront()
              end

              pauseBtn:toFront()
    ```

1.  当游戏取消暂停时，让物理效果再次激活，并移除所有暂停显示对象：

    ```kt
              else

                if shade then
                  display.remove( shade )
                  shade = nil
                end

                if pauseBG then
                  pauseBG.isVisible = false
                  pauseBG.isActive = false
                end

                gameIsActive = true
                physics.start()

                local function resumeGame()
                timer.resume( startDrop )
                print("timer has been resumed")
              end
              timer.performWithDelay(1, resumeGame)

            end
          end
        end
    ```

1.  在`onPauseTouch()`函数后添加`pauseBtn` UI 按钮和`pauseBG`显示对象：

    ```kt
        pauseBtn = ui.newButton{
          defaultSrc = "pausebtn.png",
          defaultX = 44,
          defaultY = 44,
          overSrc = "pausebtn-over.png",
          overX = 44,
          overY = 44,
          onEvent = onPauseTouch,
          id = "PauseButton",
          text = "",
          font = "Helvetica",
          textColor = { 255, 255, 255, 255 },
          size = 16,
          emboss = false
        }

        pauseBtn.x = 38; pauseBtn.y = 288
        pauseBtn.isVisible = false
        pauseBtn.isActive = false

        gameGroup:insert( pauseBtn )

        pauseBG = display.newImageRect( "pauseoverlay.png", 480, 320 )
        pauseBG.x = 240; pauseBG.y = 160
        pauseBG.isVisible = false
        pauseBG.isActive = false

        gameGroup:insert( pauseBG )
    ```

1.  为了让`pauseBtn`在游戏过程中显示，需要在`gameActivate()`函数中使其可见并激活：

    ```kt
        pauseBtn.isVisible = true
        pauseBtn.isActive = true
    ```

1.  游戏结束时，在`callGameOver()`函数中禁用`pauseBtn`，将代码放在`physics.pause()`行之后：

    ```kt
        pauseBtn.isVisible = false
        pauseBtn.isActive = false
    ```

    ![动作时间——暂停游戏](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_08_02.jpg)

## *刚才发生了什么？*

我们创建了`onPauseTouch(event)`函数，以控制游戏过程中发生的所有暂停事件。为了暂停游戏中的所有动作，我们将`gameIsActive`的布尔值改为`false`，并使用`physics.pause()`函数停止所有正在下落的鸡蛋。接下来，`startDrop`的计时器暂停，只要暂停功能仍然有效，从天空中下落的鸡蛋就不会随时间累积。

当按下暂停按钮时，会出现一个名为`shade`的略微透明的覆盖层。这将分散玩家对游戏场景的注意力，并让用户区分游戏是否处于非活动状态。

**游戏暂停**横幅也会在屏幕顶部显示，通过设置为可见和活动状态。`pauseBG`对象通过`pauseBG:toFront()`被推到显示层次结构的前面。

为了取消暂停游戏，我们反向执行了暂停显示项出现的过程。当`pauseBtn`第二次被按下时，通过`display.remove(shade); shade = nil`移除`shade`。`pauseBG.isVisible`和`pauseBG.isActive`属性都被设置为`false`。

记住我们之前将`gameIsActive`设置为`false`，现在是将它设回`true`的时候了。这也意味着通过`physics.start()`恢复物理效果。计时器通过`resumeGame()`本地函数恢复，并在函数中调用`timer.resume(startDrop)`。

`pauseBtn`和`pauseBG`显示对象被插入到`if`语句块的末尾。一旦游戏可以玩，`pauseBtn`对象就会显示为可见和活动状态。当**游戏结束**屏幕出现时，它是不可见和非活动的，这样当游戏结束时就不会有其他触摸事件干扰。

# Composer API

Composer API 为开发者提供了一个简单的解决方案，用于控制具有或不具有过渡效果的场景。这是一个很棒的场景管理库，可以显示菜单系统，甚至管理游戏中的多个关卡。Composer 还附带多种过渡效果。更多信息可以在 Corona 文档中找到，地址是[`docs.coronalabs.com/api/library/composer/index.html`](http://docs.coronalabs.com/api/library/composer/index.html)。

我们的场景管理与在[`docs.coronalabs.com/api/library/composer/index.html#scene-template`](http://docs.coronalabs.com/api/library/composer/index.html#scene-template)展示的场景模板相似。

## 使用 Composer API 进行游戏开发

你可能会好奇我们如何将 Composer 应用于 Egg Drop。这真的很简单。我们只需修改游戏代码中的一些行，使其与 Composer 兼容，并为游戏开始前应用的菜单系统创建一些新场景。

# 动手时间——修改游戏文件

我们将当前的`main.lua`文件重命名为`maingame.lua`，并在游戏代码中添加一些额外的行。确保在`Egg Drop`项目文件夹中*更改*文件名。按照以下步骤重命名文件：

1.  删除代码顶部附近的以下行。我们将在本章后面创建的另一个场景中隐藏状态栏。`gameGroup`显示组将被修改以适应 Composer 参数：

    ```kt
    display.setStatusBar( display.HiddenStatusBar )
    local gameGroup = display.newGroup()
    ```

1.  在代码的最顶部，通过添加`local composer = require( "composer" )`和`local scene = composer.newScene()`来实现 Composer，这样我们就可以调用场景事件：

    ```kt
    local composer = require( "composer" )
    local scene = composer.newScene()
    ```

1.  在`local loadValue = function( strFilename )`之后，在`create()`事件中添加。我们还将重新添加我们的`gameGroup`显示组，但位于场景的 view 属性下。同时，加入`composer.removeScene( "loadgame" )`。本章后面将介绍`"loadgame"`场景：

    ```kt
    -- Called when the scene's view does not exist:
    function scene:create ( event )
      local gameGroup = self.view

      -- completely remove loadgame's view
      composer.removeScene( "loadgame" )

      print( "\nmaingame: create event")
    end
    ```

1.  在`create()`事件之后，创建`show()`事件，并将其放在`gameActivate()`函数之前。`show()`事件将过渡我们所有的游戏玩法功能到屏幕上。同时，也将`gameGroup`包含在场景的 view 属性中：

    ```kt
    -- Called immediately after scene has moved onscreen:
    function scene:show( event )
      local gameGroup = self.view
    ```

1.  在`gameStart()`函数之后，删除`return gameGroup`行：

    ```kt
    return gameGroup -- Code will not run if this line is not removed 
    ```

1.  接下来，用`end`关闭`function scene: show( event )`：

    ```kt
      print( "maingame: show event" )

    end
    ```

1.  创建`hide()`和`destroy()`事件：

    ```kt
    -- Called when scene is about to move offscreen:
    function scene:hide( event )

      print( "maingame: hide event" )

    end

    -- Called prior to the removal of scene's "view" (display group)
    function scene:destroy( event )

      print( "destroying maingame's view" )

    end 
    ```

1.  最后，为所有场景事件创建事件监听器，并在代码末尾添加`return scene`：

    ```kt
    -- "create" event is dispatched if scene's view does not exist
    scene:addEventListener( "create", scene )

    -- "show" event is dispatched whenever scene transition has finished
    scene:addEventListener( "show", scene )

    -- "hide" event is dispatched before next scene's transition begins
    scene:addEventListener( "hide", scene )

    -- "destroy" event is dispatched before view is unloaded, which can be
    scene:addEventListener( "destroy", scene )

    return scene 
    ```

## *刚才发生了什么？*

使用 Composer API 将帮助我们更容易、更快速地过渡场景。每次你想将一个新场景加载到视图中时，需要添加`require("composer")`。`local scene = composer.newScene()`声明将允许我们调用场景事件，`create()`，`show()`，`hide()`，和`destroy()`。

在游戏代码的最后，我们为所有场景事件和`return scene`添加了事件监听器。

使用 Composer 管理每个场景的格式将与前面的代码类似。大部分游戏代码将在`create()`和`show()`事件显示场景时派发。当你想要清理或卸载监听器、音频、资源等时，将使用`hide()`和`destroy()`事件。

# 组织游戏

我们习惯于将`main.lua`作为我们的主源文件，以显示游戏代码的每个细节。现在是时候通过 Composer API 有效地组织它了。

# 行动时间——添加新的 main.lua 文件

使用 Composer 时，我们的`main.lua`文件仍然至关重要，因为它是 Corona SDK 启动模拟器中的应用程序时首先要查看的内容。我们将添加一些代码行，这些代码行将改变我们游戏的场景：

1.  创建一个名为`main.lua`的新文件，并将其重新添加到我们的状态栏中：

    ```kt
    display.setStatusBar( display.HiddenStatusBar )
    ```

1.  导入 Composer 并加载名为`loadmainmenu`的第一个场景。我们将在接下来的几节中创建这个场景：

    ```kt
    -- require controller module
    local composer = require ( "composer" )

    -- load first screen
    composer.gotoScene( "loadmainmenu" )
    ```

## *刚才发生了什么？*

为了在应用程序中整合 Composer，我们调用了`local composer = require ( "composer" )`模块。场景将使用`composer.gotoScene( "loadmainmenu" )`进行更改，这是一个引导用户进入主菜单屏幕的加载屏幕。

# 新的游戏过渡

既然我们已经介绍了 Composer API，我们可以应用一些期待已久的过渡效果，这将对我们的游戏有所帮助。一种方法是游戏结束后退出游戏。

# 动手时间——游戏结束后切换屏幕

既然我们已经重命名了游戏文件，让我们添加一个场景过渡，这样游戏结束后就不会停留在**游戏结束**屏幕了。要更改屏幕，请执行以下步骤：

1.  在我们的`maingame.lua`文件中，加入一个名为`local menuBtn`的新变量，其他所有变量都在代码开始时初始化。在`callGameOver()`函数内，在`highScoreText`代码之后添加以下几行：

    ```kt
        local onMenuTouch = function( event )
          if event.phase == "release" then
            audio.play( btnSound )
            composer.gotoScene( "mainmenu", "fade", 500  )

          end
        end

        menuBtn = ui.newButton{
          defaultSrc = "menubtn.png",
          defaultX = 60,
          defaultY = 60,
          overSrc = "menubtn-over.png",
          overX = 60,
          overY = 60,
          onEvent = onMenuTouch,
          id = "MenuButton",
          text = "",
          -- Can use any font available per platform
          font = "Helvetica",   
          textColor = { 255, 255, 255, 255 },
          size = 16,
          emboss = false
        }

        menuBtn.x = 100; menuBtn.y = 260

        gameGroup:insert( menuBtn )
    ```

    ![动手时间——游戏结束后切换屏幕](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_08_03.jpg)

## *刚才发生了什么？*

为了从游戏结束屏幕过渡出去，我们创建了一个菜单按钮来更改场景。在`onMenuTouch()`函数中，在按钮释放时，我们调用了`composer.gotoScene( "mainmenu", "fade", 500 )`。这将允许应用程序在 500 毫秒内使用淡入淡出效果过渡到主菜单，我们将在本章后面创建这个效果。

## 动手英雄——重新开始游戏

既然你已经充分了解 Composer API 如何与更改场景以及使用 UI 按钮在它们之间过渡，那么何不创建一个按钮，在游戏结束屏幕出现后重新开始游戏呢？到目前为止，该应用程序允许用户在游戏结束时返回菜单屏幕。

在`callGameOver()`函数内，需要创建一个新的本地函数，该函数将使用 UI 按钮系统运行事件，通过 Composer 更改场景。注意，如果你当前已经在该场景中，则不能再次调用同一场景。

# 创建一个加载屏幕

加载屏幕提供了程序正在加载过程中的反馈。这有助于告知用户下一个屏幕正在加载，这样他们就不会认为应用程序已经崩溃了，尤其是如果下一个屏幕正在加载大量数据时。

# 动手时间——添加加载屏幕

我们将在应用程序启动和游戏关卡开始之前放置加载屏幕。这告诉用户更多内容或信息即将到来。

1.  在你的项目文件夹中创建一个名为`loadmainmenu.lua`的新文件。

1.  导入 Composer 并在其中加入`composer.newScene()`函数：

    ```kt
    local composer = require( "composer" )
    local scene = composer.newScene()
    ```

1.  创建两个名为`myTimer`和`loadingImage`的本地变量。加入`create()`事件和一个`sceneGroup`显示组：

    ```kt
    local myTimer
    local loadingImage

    -- Called when the scene's view does not exist:
    function scene:create( event )
      local sceneGroup = self.view

      print( "\nloadmainmenu: create event" )
    end
    ```

1.  创建`show()`事件并加入一个`sceneGroup`显示组：

    ```kt
      -- Called immediately after scene has moved onscreen:
    function scene:show( event )
      local sceneGroup = self.view

      print( "loadmainmenu: show event" )
    ```

1.  引入`loadingImage`显示对象：

    ```kt
      loadingImage = display.newImageRect( "loading.png", 480, 320)
      loadingImage.x = 240; loadingImage.y = 160
      sceneGroup:insert( loadingImage )
    ```

1.  创建另一个名为`goToMenu()`的本地函数，并调用`composer.gotoScene( "mainmenu", "zoomOutInFadeRotate", 500 )`以将场景更改为`"mainmenu"`：

    ```kt
        local goToMenu = function()
          composer.gotoScene( "mainmenu", "zoomOutInFadeRotate", 500)
        end
    ```

1.  使用`timer`函数，每 1,000 毫秒调用一次`goToMenu()`。使用`myTimer`计时器 ID 定义它。使用`end`结束`show()`事件：

    ```kt
        myTimer = timer.performWithDelay( 1000, goToMenu, 1 )
      end
    ```

1.  调用`hide()`和`destroy()`事件。在`hide()`事件中，取消`myTimer`：

    ```kt
    -- Called when scene is about to move offscreen:
    function scene:hide()

      if myTimer then timer.cancel( myTimer ); end

      print( "loadmainmenu: hide event" )

    end

    -- Called prior to the removal of scene's "view" (display group)
    function scene:destroy( event )

      print( "destroying loadmainmenu's view" )
    end
    ```

1.  为所有场景事件和`return scene`添加事件监听器。保存并关闭文件：

    ```kt
    -- "create" event is dispatched if scene's view does not exist
    scene:addEventListener( "create", scene )

    -- "show" event is dispatched whenever scene transition has finished
    scene:addEventListener( "show", scene )

    -- "hide" event is dispatched before next scene's transition begins
    scene:addEventListener( "hide", scene )

    -- "destroy" event is dispatched before view is unloaded, which can be
    scene:addEventListener( "destroy", scene )

    return scene
    ```

1.  在你的项目文件夹中创建一个名为`loadgame.lua`的新文件。我们将制作一个在游戏场景`maingame.lua`之前出现的加载屏幕。使用`composer.gotoScene( "maingame", "flipFadeOutIn", 500 )`进行场景过渡。保存并关闭你的文件：

    ```kt
    local composer = require( "composer" )
    local scene = composer.newScene()

    local myTimer
    local loadingImage

    -- Called when the scene's view does not exist:
    function scene:create( event )
      local sceneGroup = self.view

      -- completely remove mainmenu
      composer.removeScene( "mainmenu" )

      print( "\nloadgame: create event" )
    end

    -- Called immediately after scene has moved onscreen:
    function scene:show( event )
      local sceneGroup = self.view

      print( "loadgame: show event" )

      loadingImage = display.newImageRect( "loading.png", 480, 320)
      loadingImage.x = 240; loadingImage.y = 160
      sceneGroup:insert( loadingImage )

      local changeScene = function()
        composer.gotoScene( "maingame", "flipFadeOutIn", 500 )
      end
      myTimer = timer.performWithDelay( 1000, changeScene, 1 )

    end

    -- Called when scene is about to move offscreen:
    function scene:hide()

      if myTimer then timer.cancel( myTimer ); end

      print( "loadgame: hide event" )

    end

    -- Called prior to the removal of scene's "view" (display group)
    function scene:destroy( event )

      print( "destroying loadgame's view" )
    end

    -- "create" event is dispatched if scene's view does not exist
    scene:addEventListener( "create", scene )

    -- "show" event is dispatched whenever scene transition has finished
    scene:addEventListener( "show", scene )

    -- "hide" event is dispatched before next scene's transition begins
    scene:addEventListener( "hide", scene )

    -- "destroy" event is dispatched before view is unloaded, which can be
    scene:addEventListener( "destroy", scene )

    return scene
    ```

    ![行动时间 - 添加加载屏幕](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_08_04.jpg)

## *刚才发生了什么？*

在`loadmainmenu.lua`文件中，一旦`loadingImage`被添加到屏幕上，我们就创建了`goToMenu()`函数，以将场景更改为`"mainmenu"`，并使用`"zoomOutInFadeRotate"`过渡，让加载屏幕图像在淡出至背景时缩小并旋转。`myTimer = timer.performWithDelay( 1000, goToMenu, 1 )`语句在 1,000 毫秒（一秒）后执行该函数，并且只运行一次。这足够时间查看图像并让它淡出。

所有显示对象通过`function scene:show( event )`进入场景。`loadingImage`对象被放置在`sceneGroup`中。为了确保场景更改后没有定时器在运行，`myTimer`在`function scene:hide()`下使用`timer.cancel(myTimer)`停止运行。

`loadgame.lua`的代码与`loadmainmenu.lua`类似。对于这个文件，Composer 将场景过渡到`maingame.lua`，即游戏玩法文件。

# 创建主菜单

主菜单或标题屏幕是玩家在玩游戏之前看到的第一印象之一。它通常显示与实际游戏相关的小图像或风景片段，并显示应用程序的标题。

有一些如**开始**或**播放**的按钮，鼓励玩家如果他们选择的话进入游戏，还有一些次要的按钮如**选项**查看设置和其他信息。

# 行动时间 - 添加主菜单

我们将通过引入游戏标题和**播放**和**选项**按钮来创建游戏的前端，这些按钮将在应用程序的不同场景中轻松过渡。

1.  创建一个名为`mainmenu.lua`的新文件，并导入 Composer 和 UI 模块，`composer.newScene()`函数，以及定时器和音频的变量：

    ```kt
    local composer = require( "composer" )
    local scene = Composer.newScene()

    local ui = require("ui")

    local btnAnim

    local btnSound = audio.loadSound( "btnSound.wav" )
    ```

1.  创建`create()`事件。添加`composer.removeScene( "maingame" )`和`composer.removeScene( "options" )`行，这将移除`"maingame"`和`"options"`场景。可以在玩家从主游戏屏幕过渡并返回主菜单屏幕后移除`"maingame"`。可以在玩家从选项屏幕过渡并返回主菜单屏幕后移除`"options"`：

    ```kt
    -- Called when the scene's view does not exist:
    function scene:create( event )
      local sceneGroup = self.view

      -- completely remove maingame and options
      composer.removeScene( "maingame" )
      composer.removeScene( "options" )

      print( "\nmainmenu: create event" )
    end
    ```

1.  在`show()`事件中添加`backgroundImage`显示对象；

    ```kt
    -- Called immediately after scene has moved onscreen:
    function scene:show( event )
      local sceneGroup = self.view

      print( "mainmenu: show event" )

      local backgroundImage = display.newImageRect( "mainMenuBG.png", 480, 320 )
      backgroundImage.x = 240; backgroundImage.y = 160
      sceneGroup:insert( backgroundImage )
    ```

1.  引入`playBtn`显示对象，并创建一个名为`onPlayTouch(event)`的函数，该函数使用`composer.gotoScene()`将场景更改为`"loadgame"`。使用`"fade"`效果进行场景变换：

    ```kt
      local playBtn

      local onPlayTouch = function( event )
        if event.phase == "release" then

          audio.play( btnSound )
          composer.gotoScene( "loadgame", "fade", 300  )

        end
      end

      playBtn = ui.newButton{
        defaultSrc = "playbtn.png",
        defaultX = 100,
        defaultY = 100,
        overSrc = "playbtn-over.png",
        overX = 100,
        overY = 100,
        onEvent = onPlayTouch,
        id = "PlayButton",
        text = "",
        font = "Helvetica",
        textColor = { 255, 255, 255, 255 },
        size = 16,
        emboss = false
      }

      playBtn.x = 240; playBtn.y = 440
        sceneGroup:insert( playBtn )
    ```

1.  使用`easing.inOutExpo`过渡，在 500 毫秒内将`playBtn`显示对象转换到 y=260 的位置。通过`btnAnim`进行初始化：

    ```kt
    btnAnim = transition.to( playBtn, { time=1000, y=260, transition=easing.inOutExpo } )
    ```

1.  引入`optBtn`显示对象，并创建一个名为`onOptionsTouch(event)`的函数。使用`composer.gotoScene()`以`"crossFade"`效果将场景过渡到`"options"`：

    ```kt
    local optBtn

      local onOptionsTouch = function( event )
        if event.phase == "release" then

          audio.play( btnSound )
          composer.gotoScene( "options", "crossFade", 300)

        end
      end

      optBtn = ui.newButton{
        defaultSrc = "optbtn.png",
        defaultX = 60,
        defaultY = 60,
        overSrc = "optbtn-over.png",
        overX = 60,
        overY = 60,
        onEvent = onOptionsTouch,
        id = "OptionsButton",
        text = "",
        font = "Helvetica",
        textColor = { 255, 255, 255, 255 },
        size = 16,
        emboss = false
      }
      optBtn.x = 430; optBtn.y = 440
      sceneGroup:insert( optBtn )
    ```

1.  使用`easing.inOutExpo`过渡，在 500 毫秒内将`optBtn`显示对象转换到`y = 280`的位置。通过`btnAnim`进行初始化。使用`end`结束`scene:show( event )`函数：

    ```kt
      btnAnim = transition.to( optBtn, { time=1000, y=280, transition=easing.inOutExpo } )

    end
    ```

1.  创建`hide()`事件并取消`btnAnim`过渡。同时，创建`destroy()`事件：

    ```kt
    -- Called when scene is about to move offscreen:
    function scene:hide()

      if btnAnim then transition.cancel( btnAnim ); end

      print( "mainmenu: hide event" )

    end

    -- Called prior to the removal of scene's "view" (display group)
    function scene:destroy( event )

      print( "destroying mainmenu's view" )
    end
    ```

1.  为所有场景事件和`return scene`添加事件监听器。保存并关闭你的文件：

    ```kt
    -- "create" event is dispatched if scene's view does not exist
    scene:addEventListener( "create", scene )

    -- "show" event is dispatched whenever scene transition has finished
    scene:addEventListener( "show", scene )

    -- "hide" event is dispatched before next scene's transition begins
    scene:addEventListener( "hide", scene )

    -- "destroy" event is dispatched before view is unloaded, which can be
    scene:addEventListener( "destroy", scene )

    return scene
    ```

    ![行动时间 - 添加主菜单](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_08_05.jpg)

## *刚才发生了什么？*

在主菜单屏幕上，我们添加了一个显示游戏标题和**播放**及**选项**按钮的图像。此时的**选项**按钮还不起作用。`onPlayTouch()`函数将场景过渡到`"loadgame"`。这将改变到`loadgame.lua`场景。**播放**按钮位于`x = 240`; `y = 440`（居中和屏幕外）。当场景加载时，`playBtn`过渡到`y = 260`，因此它会从屏幕底部向上弹出，耗时 1000 毫秒。

**选项**按钮执行类似操作。`optBtn`对象放置在舞台右侧，并在 500 毫秒内弹出至`y = 280`。

`btnAnim`过渡通过`scene:hide()`函数中的`transition.cancel( btnAnim )`被取消。每次更改场景时清理定时器、过渡和事件监听器，以防止应用程序中可能发生的内存泄漏，这是非常重要的。

# 创建一个选项菜单

选项菜单允许用户在游戏中更改各种设置或包含无法在主菜单中显示的其他信息。游戏可以拥有许多选项，也可能只有几个。有时，选项菜单也可以称为设置菜单，为玩家的体验提供相同类型的自定义。

# 行动时间 - 添加一个选项菜单

我们将通过主菜单添加一个可以访问的选项菜单。我们将添加一个新的 UI 按钮，名为**积分**，一旦按下，它将引导用户进入积分屏幕。要添加选项菜单，请执行以下步骤：

1.  创建一个名为`options.lua`的新文件，并导入 Composer 和 UI 模块，`composer.newScene()`函数，以及定时器和音频的变量：

    ```kt
    local composer = require( "composer" )
    local scene = composer.newScene()

    local ui = require("ui")

    local btnAnim

    local btnSound = audio.loadSound( "btnSound.wav" )
    ```

1.  创建`create()`事件。加入`composer.removeScene( "mainmenu" )`，这将移除`"mainmenu"`场景。这会在玩家从主菜单屏幕过渡到选项屏幕后发生。接下来，加入`composer.removeScene( "creditsScreen" )`。这将会在玩家从积分屏幕返回到选项屏幕后移除`"creditsScreen"`：

    ```kt
    -- Called when the scene's view does not exist:
    function scene:create( event )
      local sceneGroup = self.view

      -- completely remove mainmenu and creditsScreen
      composer.removeScene( "mainmenu" )
      composer.removeScene( "creditsScreen" )

      print( "\noptions: create event" )
    end
    ```

1.  添加`show()`事件和`backgroundImage`显示对象：

    ```kt
    -- Called immediately after scene has moved onscreen:
    function scene:show( event )
      local sceneGroup = self.view

      print( "options: show event" )

      local backgroundImage = display.newImageRect( "optionsBG.png", 480, 320 )
      backgroundImage.x = 240; backgroundImage.y = 160
      sceneGroup:insert( backgroundImage )
    ```

1.  为信用屏幕创建一个按钮。在 1000 毫秒内使用`easing.inOutExpo`过渡将`creditsBtn`显示对象过渡到`y = 260`。通过`btnAnim`初始化它：

    ```kt
      local creditsBtn

      local onCreditsTouch = function( event )
        if event.phase == "release" then

          audio.play( btnSound )
          Composer.gotoScene( "creditsScreen", "crossFade", 300 )

        end
      end

      creditsBtn = ui.newButton{
        defaultSrc = "creditsbtn.png",
        defaultX = 100,
        defaultY = 100,
        overSrc = "creditsbtn-over.png",
        overX = 100,
        overY = 100,
        onEvent = onCreditsTouch,
        id = "CreditsButton",
        text = "",
        font = "Helvetica",
        textColor = { 255, 255, 255, 255 },
        size = 16,
        emboss = false
      }

      creditsBtn.x = 240; creditsBtn.y = 440
      sceneGroup:insert( creditsBtn )

      btnAnim = transition.to( creditsBtn, { time=1000, y=260, transition=easing.inOutExpo } )
    ```

1.  创建一个加载主菜单的**关闭**按钮。通过`end`结束`scene:show( event )`：

    ```kt
      local closeBtn

      local onCloseTouch = function( event )
        if event.phase == "release" then
          audio.play( tapSound )
          composer.gotoScene( "mainmenu", "zoomInOutFadeRotate", 500 ) 
        end
      end

      closeBtn = ui.newButton{
        defaultSrc = "closebtn.png",
        defaultX = 60,
        defaultY = 60,
        overSrc = "closebtn-over.png",
        overX = 60,
        overY = 60,
        onEvent = onCloseTouch,
        id = "CloseButton",
        text = "",
        font = "Helvetica",
        textColor = { 255, 255, 255, 255 },
        size = 16,
        emboss = false
      }

      closeBtn.x = 50; closeBtn.y = 280
      sceneGroup:insert( closeBtn ) 
    end
    ```

1.  创建`hide()`事件并取消`btnAnim`过渡。同时，创建`destroy()`事件。为所有场景事件和`return scene`语句添加事件监听器。保存并关闭你的文件：

    ```kt
    -- Called when scene is about to move offscreen:
    function scene:hide()

      if btnAnim then transition.cancel( btnAnim ); end

      print( "options: hide event" )

    end

    -- Called prior to the removal of scene's "view" (display group)
    function scene:destroy( event )

      print( "destroying options's view" )
    end

    -- "create" event is dispatched if scene's view does not exist
    scene:addEventListener( "create", scene )

    -- "show" event is dispatched whenever scene transition has finished
    scene:addEventListener( "show", scene )

    -- "hide" event is dispatched before next scene's transition begins
    scene:addEventListener( "hide", scene )

    -- "destroy" event is dispatched before view is unloaded, which can be
    scene:addEventListener( "destroy", scene )	

    return scene
    ```

    ![行动时间 – 添加选项菜单](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_08_06.jpg)

## *刚才发生了什么？*

在这个场景中，`creditsBtn`的操作方式与创建主菜单类似。此时的**信用**按钮尚不可用。在`onCreditsTouch()`函数中，场景过渡到`"creditsScreen"`并使用`"crossFade"`作为效果。当场景加载时，`creditsBtn`从屏幕外位置过渡到 y=260，耗时 1,000 毫秒。

为这个场景创建了一个**关闭**按钮，以便用户有一个返回上一个屏幕的方法。通过`onCloseTouch()`函数，当释放`closeBtn`时，Composer 将场景更改为`"mainmenu"`。按下关闭按钮时，将显示主菜单屏幕。`scene:hide()`函数取消了`btnAnim`过渡。

# 创建信用屏幕

信用屏幕通常会显示并列出参与游戏制作的所有人员。它还可以包括感谢某些个人和程序的信息，这些程序用于创建最终项目。

# 行动时间 – 添加信用屏幕

我们将要创建的信用屏幕将基于一个触摸事件，该事件从引入它的上一个屏幕过渡回来。要添加信用屏幕，请执行以下步骤：

1.  创建一个名为`creditsScreen.lua`的新文件，并导入 Composer、`composer.newScene()`函数和`backgroundImage`变量：

    ```kt
    local composer = require( "composer" )
    local scene = composer.newScene()

    local backgroundImage
    ```

1.  创建`create()`事件。添加`composer.removeScene("options")`行，这将移除`"options"`场景。这将在玩家从选项屏幕过渡到信用屏幕后发生：

    ```kt
    -- Called when the scene's view does not exist:
    function scene:create( event )
      local sceneGroup = self.view

      -- completely remove options
      composer.removeScene( "options" )

      print( "\ncreditsScreen: create event" )
    end
    ```

1.  添加`show()`事件和`backgroundImage`显示对象：

    ```kt
    -- Called immediately after scene has moved onscreen:
    function scene:show( event )
      local sceneGroup = self.view

      print( "creditsScreen: show event" )

      backgroundImage = display.newImageRect( "creditsScreen.png", 480, 320 )
      backgroundImage.x = 240; backgroundImage.y = 160
      sceneGroup:insert( backgroundImage )
    ```

1.  创建一个名为`changeToOptions()`的本地函数，带有一个事件参数。让该函数通过在`backgroundImage`上的触摸事件，使用 Composer 将场景改回选项屏幕。通过`end`结束`scene:show(event)`函数：

    ```kt
      local changeToOptions = function( event )
        if event.phase == "began" then

          composer.gotoScene( "options", "crossFade", 300  )

        end
      end

      backgroundImage:addEventListener( "touch", changeToOptions)
    end
    ```

1.  创建`hide()`和`destroy()`事件。为所有场景事件和`return scene`语句添加事件监听器。保存并关闭你的文件：

    ```kt
    -- Called when scene is about to move offscreen:
    function scene:hide()

      print( "creditsScreen: hide event" )

    end

    -- Called prior to the removal of scene's "view" (display group)
    function scene:destroy( event )

      print( "destroying creditsScreen's view" )
    end

    -- "create" event is dispatched if scene's view does not exist
    scene:addEventListener( "create", scene )

    -- "show" event is dispatched whenever scene transition has finished
    scene:addEventListener( "show", scene )

    -- "hide" event is dispatched before next scene's transition begins
    scene:addEventListener( "hide", scene )

    -- "destroy" event is dispatched before view is unloaded, which can be
    scene:addEventListener( "destroy", scene )

    return scene
    ```

    ![行动时间 – 添加信用屏幕](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_08_07.jpg)

## *刚才发生了什么？*

信用屏幕与事件监听器一起工作。`changeToOptions(event)`函数将告诉 Composer 使用`composer.gotoScene( "options", "crossFade", 500 )`更改场景为 `"options"`。在函数的末尾，`backgroundImage`将在屏幕被触摸时激活事件监听器。`backgroundImage`对象在`scene:show( event )`函数下的`sceneGroup`中插入。现在，Egg Drop 完全可以通过 Composer 操作。在模拟器中运行游戏。你将能够过渡到我们在本章中创建的所有场景，还可以玩游戏。

## 尝试英雄——添加更多关卡

现在，Egg Drop 已经完成，并且拥有一个工作的菜单系统，通过创建更多关卡来挑战自己。为了添加额外的关卡位置，将需要增加一些小的修改。在更改场景时请记得应用 Composer。

尝试创建以下内容：

+   关卡选择屏幕

+   添加额外关卡的关卡编号按钮

在创建新关卡时，请参考`maingame.lua`中显示的格式。新关卡可以通过改变蛋从天而降的速度间隔来改变，或者也许可以通过添加其他游戏资源来躲避以免受到惩罚。有如此多的可能性可以在这个游戏框架中添加你自己的创意。试一试吧！

## 小测验——游戏过渡和场景

Q1. 你调用哪个函数使用 Composer 更改场景？

1.  `composer()`

1.  `composer.gotoScene()`

1.  `composer(changeScene)`

1.  以上都不是

Q2. 有哪个函数可以将任何参数转换成数字或 nil？

1.  `tonumber()`

1.  `print()`

1.  `tostring()`

1.  `nil`

Q3. 你如何暂停一个计时器？

1.  `timer.cancel()`

1.  `physics.pause()`

1.  `timer.pause( timerID )`

1.  以上都不是

Q4. 你如何恢复一个计时器？

1.  `resume()`

1.  `timer.resume( timerID )`

1.  `timer.performWithDelay()`

1.  以上都不是

# 总结

恭喜你！我们已经完成了一个完整的游戏，可以进入 App Store 或 Google Play 商店。当然，我们不会使用这个确切的游戏，但你已经学到了足够多的知识去创造一个。在如此短的时间内完成游戏框架是一个了不起的成就，尤其是创造出如此简单的东西。

在本章中你学会了以下技能：

+   使用 saveValue()和 loadValue()保存高分

+   理解如何暂停物理/计时器

+   显示暂停菜单

+   使用 Composer API 更改场景

+   使用加载屏幕在场景间创建过渡

+   使用主菜单介绍游戏标题和子菜单

在本章中，我们已经取得了重要的里程碑。我们在之前章节中讨论的所有内容都被应用到了这个示例游戏中。关于它最好的事情是，我们花了不到一天的开发时间来编写代码。而艺术资源则是另一回事了。

我们还需要学习更多关于 Corona SDK 的功能。在下一章中，我们将详细探讨如何为高分辨率设备优化游戏资源。我们还将了解如何通过应用程序在 Facebook 和 Twitter 上发布消息。
