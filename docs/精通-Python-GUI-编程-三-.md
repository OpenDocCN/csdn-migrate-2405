# 精通 Python GUI 编程（三）

> 原文：[`zh.annas-archive.org/md5/0baee48435c6a8dfb31a15ece9441408`](https://zh.annas-archive.org/md5/0baee48435c6a8dfb31a15ece9441408)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分：使用外部资源

现在您已经了解了构建 PyQt GUI 的基础知识，是时候进入外部世界了。在本节中，您将学习如何将您的 PyQt 应用程序连接到外部资源，如网络和数据库。

本节包括以下章节：

+   第七章，使用 QtMultimedia 处理音频和视频

+   第八章，使用 QtNetwork 进行网络操作

+   第九章，使用 QtSQL 探索 SQL


# 第七章：使用 QtMultimedia 处理音频-视频

无论是在游戏、通信还是媒体制作应用中，音频和视频内容通常是现代应用的重要组成部分。当使用本机 API 时，即使是最简单的音频-视频（AV）应用程序在支持多个平台时也可能非常复杂。然而，幸运的是，Qt 为我们提供了一个简单的跨平台多媒体 API，即`QtMultimedia`。使用`QtMultimedia`，我们可以轻松地处理音频内容、视频内容或摄像头和收音机等设备。

在这一章中，我们将使用`QtMultimedia`来探讨以下主题：

+   简单的音频播放

+   录制和播放音频

+   录制和播放视频

# 技术要求

除了第一章中描述的基本 PyQt 设置外，您还需要确保已安装`QtMultimedia`和`PyQt.QtMultimedia`库。如果您使用`pip`安装了 PyQt5，则应该已经安装了。使用发行版软件包管理器的 Linux 用户应检查这些软件包是否已安装。

您可能还想从我们的 GitHub 存储库[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter07`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter07)下载代码，其中包含示例代码和用于这些示例的音频数据。

如果您想创建自己的音频文件进行处理，您可能需要安装免费的 Audacity 音频编辑器，网址为[`www.audacityteam.org/`](https://www.audacityteam.org/)。

最后，如果您的计算机没有工作的音频系统、麦克风和网络摄像头，您将无法充分利用本章。如果没有，那么其中一些示例将无法为您工作。

查看以下视频以查看代码的实际操作：[`bit.ly/2Mjr8vx`](http://bit.ly/2Mjr8vx)

# 简单的音频播放

很多时候，应用程序需要对 GUI 事件做出声音回应，就像在游戏中一样，或者只是为用户操作提供音频反馈。对于这种应用程序，`QtMultimedia`提供了`QSoundEffect`类。`QSoundEffect`仅限于播放未压缩音频，因此它可以使用**脉冲编码调制**（**PCM**）、**波形数据**（**WAV**）文件，但不能使用 MP3 或 OGG 文件。这样做的好处是它的延迟低，资源利用率非常高，因此虽然它不适用于通用音频播放器，但非常适合快速播放音效。

为了演示`QSoundEffect`，让我们构建一个电话拨号器。将第四章中的应用程序模板*使用 QMainWindow 构建应用程序*复制到一个名为`phone_dialer.py`的新文件中，并在编辑器中打开它。

让我们首先导入`QtMultimedia`库，如下所示：

```py
from PyQt5 import QtMultimedia as qtmm
```

导入`QtMultimedia`将是本章所有示例的必要第一步，我们将一贯使用`qtmm`作为其别名。

我们还将导入一个包含必要的 WAV 数据的`resources`库：

```py
import resources
```

这个`resources`文件包含一系列**双音多频**（**DTMF**）音调。这些是电话拨号时电话生成的音调，我们包括了`0`到`9`、`*`和`#`。我们已经在示例代码中包含了这个文件；或者，您可以从自己的音频样本创建自己的`resources`文件（您可以参考第六章中关于如何做到这一点的信息）。

您可以使用免费的 Audacity 音频编辑器生成 DTMF 音调。要这样做，请从 Audacity 的主菜单中选择生成|DTMF。

一旦完成这些，我们将创建一个`QPushButton`子类，当单击时会播放声音效果，如下所示：

```py
class SoundButton(qtw.QPushButton):

    def __init__(self, wav_file, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.wav_file = wav_file
        self.player = qtmm.QSoundEffect()
        self.player.setSource(qtc.QUrl.fromLocalFile(wav_file))
        self.clicked.connect(self.player.play)
```

如您所见，我们修改了构造函数以接受声音文件路径作为参数。这个值被转换为`QUrl`并通过`setSource()`方法传递到我们的`QSoundEffect`对象中。最后，`QSoundEffect.play()`方法触发声音的播放，因此我们将其连接到按钮的`clicked`信号。这就是创建我们的`SoundButton`对象所需的全部内容。

回到`MainWindow.__init__()`方法，让我们创建一些`SoundButton`对象并将它们排列在 GUI 中：

```py
        dialpad = qtw.QWidget()
        self.setCentralWidget(dialpad)
        dialpad.setLayout(qtw.QGridLayout())

        for i, symbol in enumerate('123456789*0#'):
            button = SoundButton(f':/dtmf/{symbol}.wav', symbol)
            row = i // 3
            column = i % 3
            dialpad.layout().addWidget(button, row, column)
```

我们已经设置了资源文件，以便可以通过`dtmf`前缀下的符号访问每个 DTMF 音调；例如，`':/dtmf/1.wav'`指的是 1 的 DTMF 音调。通过这种方式，我们可以遍历一串符号并为每个创建一个`SoundButton`对象，然后将其添加到三列网格中。

就是这样；运行这个程序并按下按钮。它应该听起来就像拨打电话！

# 录制和播放音频

`QSoundEffect`足以处理简单的事件声音，但对于更高级的音频项目，我们需要具备更多功能的东西。理想情况下，我们希望能够加载更多格式，控制播放的各个方面，并录制新的声音。

在这一部分，我们将专注于提供这些功能的两个类：

+   `QMediaPlayer`类，它类似于一个虚拟媒体播放器设备，可以加载音频或视频内容

+   `QAudioRecorder`类，用于管理将音频数据录制到磁盘

为了看到这些类的实际效果，我们将构建一个采样音效板。

# 初始设置

首先，制作一个新的应用程序模板副本，并将其命名为`soundboard.py`。然后，像上一个项目一样导入`QtMultimedia`，并布局主界面。

在`MainWindow`构造函数中，添加以下代码：

```py
        rows = 3
        columns = 3
        soundboard = qtw.QWidget()
        soundboard.setLayout(qtw.QGridLayout())
        self.setCentralWidget(soundboard)
        for c in range(columns):
            for r in range(rows):
                sw = SoundWidget()
                soundboard.layout().addWidget(sw, c, r)
```

我们在这里所做的只是创建一个空的中央小部件，添加一个网格布局，然后用`3`行`3`列的`SoundWidget`对象填充它。

# 实现声音播放

我们的`SoundWidget`类将是一个管理单个声音样本的`QWidget`对象。完成后，它将允许我们加载或录制音频样本，循环播放或单次播放，并控制其音量和播放位置。

在`MainWindow`构造函数之前，让我们创建这个类并给它一个布局：

```py
class SoundWidget(qtw.QWidget):

    def __init__(self):
        super().__init__()
        self.setLayout(qtw.QGridLayout())
        self.label = qtw.QLabel("No file loaded")
        self.layout().addWidget(self.label, 0, 0, 1, 2)
```

我们添加的第一件事是一个标签，它将显示小部件加载的样本文件的名称。我们需要的下一件事是一个控制播放的按钮。我们不只是一个普通的按钮，让我们运用一些我们的样式技巧来创建一个可以在播放按钮和停止按钮之间切换的自定义按钮。 

在`SoundWidget`类的上方开始一个`PlayButton`类，如下所示：

```py
class PlayButton(qtw.QPushButton):
    play_stylesheet = 'background-color: lightgreen; color: black;'
    stop_stylesheet = 'background-color: darkred; color: white;'

    def __init__(self):
        super().__init__('Play')
        self.setFont(qtg.QFont('Sans', 32, qtg.QFont.Bold))
        self.setSizePolicy(
            qtw.QSizePolicy.Expanding,
            qtw.QSizePolicy.Expanding
        )
        self.setStyleSheet(self.play_stylesheet)
```

回到`SoundWidget`类，我们将添加一个`PlayButton`对象，如下所示：

```py
        self.play_button = PlayButton()
        self.layout().addWidget(self.play_button, 3, 0, 1, 2)
```

现在我们有了一个控制按钮，我们需要创建将播放采样的`QMediaPlayer`对象，如下所示：

```py
        self.player = qtmm.QMediaPlayer()
```

您可以将`QMediaPlayer`视为硬件媒体播放器（如 CD 或蓝光播放器）的软件等效物。就像硬件媒体播放器有播放、暂停和停止按钮一样，`QMediaPlayer`对象有`play()`、`stop()`和`pause()`槽来控制媒体的播放。

让我们将我们的双功能`PlayButton`对象连接到播放器。我们将通过一个名为`on_playbutton()`的实例方法来实现这一点：

```py
        self.play_button.clicked.connect(self.on_playbutton)
```

`SoundWidget.on_playbutton()`将如何看起来：

```py
    def on_playbutton(self):
        if self.player.state() == qtmm.QMediaPlayer.PlayingState:
            self.player.stop()
        else:
            self.player.play()
```

这种方法检查了播放器对象的`state`属性，该属性返回一个常量，指示播放器当前是正在播放、已暂停还是已停止。如果播放器当前正在播放，我们就停止它；如果没有，我们就要求它播放。

由于我们的按钮在播放和停止按钮之间切换，让我们更新它的标签和外观。`QMediaPlayer`在其状态改变时发出`stateChanged`信号，我们可以将其发送到我们的`PlayButton`对象，如下所示：

```py
        self.player.stateChanged.connect(self.play_button.on_state_changed)
```

回到`PlayButton`类，让我们处理该信号，如下所示：

```py
    def on_state_changed(self, state):
        if state == qtmm.QMediaPlayer.PlayingState:
            self.setStyleSheet(self.stop_stylesheet)
            self.setText('Stop')
        else:
            self.setStyleSheet(self.play_stylesheet)
            self.setText('Play')
```

在这里，`stateChanged`传递了媒体播放器的新状态，我们用它来设置按钮的播放或停止外观。

# 加载媒体

就像硬件媒体播放器需要加载 CD、DVD 或蓝光光盘才能实际播放任何内容一样，我们的`QMediaPlayer`在播放任何音频之前也需要加载某种内容。让我们探讨如何从文件中加载声音。

首先在`SoundWidget`布局中添加一个按钮，如下所示：

```py
        self.file_button = qtw.QPushButton(
            'Load File', clicked=self.get_file)
        self.layout().addWidget(self.file_button, 4, 0)
```

这个按钮调用`get_file()`方法，看起来是这样的：

```py
    def get_file(self):
        fn, _ = qtw.QFileDialog.getOpenFileUrl(
            self,
            "Select File",
            qtc.QDir.homePath(),
            "Audio files (*.wav *.flac *.mp3 *.ogg *.aiff);; All files (*)"
        )
        if fn:
            self.set_file(fn)
```

这个方法简单地调用`QFileDialog`来检索文件 URL，然后将其传递给另一个方法`set_file()`，我们将在下面编写。我们已经设置了过滤器来查找五种常见的音频文件类型，但如果你有不同格式的音频，可以随意添加更多——`QMediaPlayer`在加载方面非常灵活。

请注意，我们正在调用`getOpenFileUrl()`，它返回一个`QUrl`对象，而不是文件路径字符串。`QMediaPlayer`更喜欢使用`QUrl`对象，因此这将节省我们一个转换步骤。

`set_file()`方法是我们最终将媒体加载到播放器中的地方：

```py
    def set_file(self, url):
        content = qtmm.QMediaContent(url)
        self.player.setMedia(content)
        self.label.setText(url.fileName())
```

在我们可以将 URL 传递给媒体播放器之前，我们必须将其包装在`QMediaContent`类中。这为播放器提供了播放内容所需的 API。一旦包装好，我们就可以使用`QMediaPlayer.setMedia()`来加载它，然后它就准备好播放了。你可以将这个过程想象成将音频数据放入 CD（`QMediaContent`对象），然后将 CD 加载到 CD 播放器中（使用`setMedia()`）。

作为最后的修饰，我们已经检索了加载文件的文件名，并将其放在标签中。

# 跟踪播放位置

此时，我们的声音板可以加载和播放样本，但是看到并控制播放位置会很好，特别是对于长样本。`QMediaPlayer`允许我们通过信号和槽来检索和控制播放位置，所以让我们从我们的 GUI 中来看一下。

首先创建一个`QSlider`小部件，如下所示：

```py
        self.position = qtw.QSlider(
            minimum=0, orientation=qtc.Qt.Horizontal)
        self.layout().addWidget(self.position, 1, 0, 1, 2)
```

`QSlider`是一个我们还没有看过的小部件；它只是一个滑块控件，可以用来输入最小值和最大值之间的整数。

现在连接滑块和播放器，如下所示：

```py
        self.player.positionChanged.connect(self.position.setSliderPosition)
        self.player.durationChanged.connect(self.position.setMaximum)
        self.position.sliderMoved.connect(self.player.setPosition)
```

`QMediaPlayer`类以表示从文件开始的毫秒数的整数报告其位置，因此我们可以将`positionChanged`信号连接到滑块的`setSliderPosition()`槽。

然而，我们还需要调整滑块的最大位置，使其与样本的持续时间相匹配，否则滑块将不知道值代表的百分比。因此，我们已经将播放器的`durationChanged`信号（每当新内容加载到播放器时发出）连接到滑块的`setMaximum()`槽。

最后，我们希望能够使用滑块来控制播放位置，因此我们将`sliderMoved`信号设置为播放器的`setPosition()`槽。请注意，我们绝对要使用`sliderMoved`而不是`valueChanged`（当用户*或*事件更改值时，`QSlider`发出的信号），因为后者会在媒体播放器更改位置时创建一个反馈循环。

这些连接是我们的滑块工作所需的全部。现在你可以运行程序并加载一个长声音；你会看到滑块跟踪播放位置，并且可以在播放之前或期间移动以改变位置。

# 循环音频

在一次性播放我们的样本很好，但我们也想循环播放它们。在`QMediaPlayer`对象中循环音频需要稍微不同的方法。我们需要先将`QMediaContent`对象添加到`QMediaPlayList`对象中，然后告诉播放列表循环播放。

回到我们的`set_file()`方法，我们需要对我们的代码进行以下更改：

```py
    def set_file(self, url):
        self.label.setText(url.fileName())
        content = qtmm.QMediaContent(url)
        #self.player.setMedia(content)
        self.playlist = qtmm.QMediaPlaylist()
        self.playlist.addMedia(content)
        self.playlist.setCurrentIndex(1)
        self.player.setPlaylist(self.playlist)
```

当然，一个播放列表可以加载多个文件，但在这种情况下，我们只想要一个。我们使用`addMedia（）`方法将`QMediaContent`对象加载到播放列表中，然后使用`setCurrentIndex（）`方法将播放列表指向该文件。请注意，播放列表不会自动指向任何项目。这意味着如果您跳过最后一步，当您尝试播放播放列表时将不会发生任何事情。

最后，我们使用媒体播放器的`setPlaylist（）`方法添加播放列表。

现在我们的内容在播放列表中，我们将创建一个复选框来切换循环播放的开关：

```py
        self.loop_cb = qtw.QCheckBox(
            'Loop', stateChanged=self.on_loop_cb)
        self.layout().addWidget(self.loop_cb, 2, 0)
```

正如您所看到的，我们正在将复选框的`stateChanged`信号连接到一个回调方法；该方法将如下所示：

```py
    def on_loop_cb(self, state):
        if state == qtc.Qt.Checked:
            self.playlist.setPlaybackMode(
                qtmm.QMediaPlaylist.CurrentItemInLoop)
        else:
            self.playlist.setPlaybackMode(
                qtmm.QMediaPlaylist.CurrentItemOnce)
```

`QMediaPlaylist`类的`playbackMode`属性与 CD 播放器上的曲目模式按钮非常相似，可以用于在重复、随机或顺序播放之间切换。如下表所示，有五种播放模式：

| 模式 | 描述 |
| --- | --- |
| `CurrentItemOnce` | 播放当前曲目一次，然后停止。 |
| `CurrentItemInLoop` | 重复播放当前项目。 |
| `顺序` | 播放所有项目，然后停止。 |
| `循环` | 播放所有项目，然后重复。 |
| `随机` | 以随机顺序播放所有项目。 |

在这种方法中，我们根据复选框是否被选中来在`CurrentItemOnce`和`CurrentItemInLoop`之间切换。由于我们的播放列表只有一个项目，剩下的模式是没有意义的。

最后，当加载新文件时，我们将清除复选框。因此，请将以下内容添加到`set_file（）`的末尾：

```py
        self.loop_cb.setChecked(False)
```

在这一点上，您应该能够运行程序并循环播放示例。请注意，使用此方法循环音频可能无法保证无缝循环；取决于您的平台和系统功能，循环的迭代之间可能会有一个小间隙。

# 设置音量

我们的最终播放功能将是音量控制。为了让我们能够控制播放级别，`QMediaPlayer`有一个接受值从`0`（静音）到`100`（最大音量）的`volume`参数。

我们将简单地添加另一个滑块小部件来控制音量，如下所示：

```py
        self.volume = qtw.QSlider(
            minimum=0,
            maximum=100,
            sliderPosition=75,
            orientation=qtc.Qt.Horizontal,
            sliderMoved=self.player.setVolume
        )
        self.layout().addWidget(self.volume, 2, 1)
```

在设置最小和最大值后，我们只需要将`sliderMoved`连接到媒体播放器的`setVolume（）`槽。就是这样！

为了更平滑地控制音量，Qt 文档建议将滑块的线性刻度转换为对数刻度。我们建议您阅读[`doc.qt.io/qt-5/qaudio.html#convertVolume`](https://doc.qt.io/qt-5/qaudio.html#convertVolume)，看看您是否可以自己做到这一点。

# 实现录音

Qt 中的音频录制是通过`QAudioRecorder`类实现的。就像`QMediaPlayer`类类似于媒体播放设备一样，`QAudioRecorder`类类似于媒体录制设备，例如数字音频录音机（或者如果您是作者的一代人，磁带录音机）。录音机使用`record（）`、`stop（）`和`pause（）`方法进行控制，就像媒体播放器对象一样。

让我们向我们的`SoundWidget`添加一个录音机对象，如下所示：

```py
        self.recorder = qtmm.QAudioRecorder()
```

为了控制录音机，我们将创建另一个双功能按钮类，类似于我们之前创建的播放按钮：

```py
class RecordButton(qtw.QPushButton):

    record_stylesheet = 'background-color: black; color: white;'
    stop_stylesheet = 'background-color: darkred; color: white;'

    def __init__(self):
        super().__init__('Record')

    def on_state_changed(self, state):
        if state == qtmm.QAudioRecorder.RecordingState:
            self.setStyleSheet(self.stop_stylesheet)
            self.setText('Stop')
        else:
            self.setStyleSheet(self.record_stylesheet)
            self.setText('Record')
```

就像`PlayButton`类一样，每当从录音机的`stateChanged`信号接收到新的`state`值时，我们就会切换按钮的外观。在这种情况下，我们正在寻找录音机的`RecordingState`状态。

让我们向我们的小部件添加一个`RecordButtoon（）`方法，如下所示：

```py
        self.record_button = RecordButton()
        self.recorder.stateChanged.connect(
            self.record_button.on_state_changed)
        self.layout().addWidget(self.record_button, 4, 1)
        self.record_button.clicked.connect(self.on_recordbutton)
```

我们已经将`clicked`信号连接到`on_recordbutton（）`方法，该方法将处理音频录制的开始和停止。

这个方法如下：

```py
    def on_recordbutton(self):
        if self.recorder.state() == qtmm.QMediaRecorder.RecordingState:
            self.recorder.stop()
            url = self.recorder.actualLocation()
            self.set_file(url)
```

我们将首先检查录音机的状态。如果它当前正在录制，那么我们将通过调用`recorder.stop()`来停止它，这不仅会停止录制，还会将录制的数据写入磁盘上的音频文件。然后，我们可以通过调用录音机的`actualLocation()`方法来获取该文件的位置。此方法返回一个`QUrl`对象，我们可以直接将其传递给`self.set_file()`以将我们的播放设置为新录制的文件。

确保使用`actualLocation()`获取文件的位置。可以使用`setLocation()`配置录制位置，并且此值可以从`location()`访问器中获取。但是，如果配置的位置无效或不可写，Qt 可能会回退到默认设置。`actualLocation()`返回文件实际保存的 URL。

如果我们当前没有录制，我们将通过调用`recorder.record()`来告诉录音机开始录制：

```py
        else:
            self.recorder.record()
```

当调用`record()`时，音频录制器将在后台开始录制音频，并将一直保持录制，直到调用`stop()`。

在我们可以播放录制的文件之前，我们需要对`set_file()`进行一次修复。在撰写本文时，`QAudioRecorder.actualLocation()`方法忽略了向 URL 添加方案值，因此我们需要手动指定这个值：

```py
    def set_file(self, url):
        if url.scheme() == '':
            url.setScheme('file')
        content = qtmm.QMediaContent(url)
        #...
```

在`QUrl`术语中，`scheme`对象指示 URL 的协议，例如 HTTP、HTTPS 或 FTP。由于我们正在访问本地文件，因此方案应为`'file'`。

如果`QAudioRecorder`的默认设置在您的系统上正常工作，则应该能够录制和播放音频。但是，这是一个很大的*如果*；很可能您需要对音频录制器对象进行一些配置才能使其正常工作。让我们看看如何做到这一点。

# 检查和配置录音机

即使`QAudioRecorder`类对您来说运行良好，您可能会想知道是否有一种方法可以控制它记录的音频类型和质量，它从哪里记录音频，以及它将音频文件写入的位置。

为了配置这些内容，我们首先必须知道您的系统支持什么，因为对不同音频录制功能的支持可能取决于硬件、驱动程序或操作系统的能力。`QAudioRecorder`有一些方法可以提供有关可用功能的信息。

以下脚本将显示有关系统支持的音频功能的信息：

```py
from PyQt5.QtCore import *
from PyQt5.QtMultimedia import *

app = QCoreApplication([])
r = QAudioRecorder()
print('Inputs: ', r.audioInputs())
print('Codecs: ', r.supportedAudioCodecs())
print('Sample Rates: ', r.supportedAudioSampleRates())
print('Containers: ', r.supportedContainers())
```

您可以在您的系统上运行此脚本并获取受支持的`Inputs`、`Codecs`、`Sample Rates`和`container`格式的列表。例如，在典型的 Microsoft Windows 系统上，您的结果可能如下所示：

```py
Inputs:  ['Microhpone (High Defnition Aud']
Codecs:  ['audio/pcm']
Sample Rates:  ([8000, 11025, 16000, 22050, 32000,
                 44100, 48000, 88200, 96000, 192000], False)
Containers:  ['audio/x-wav', 'audio/x-raw']
```

要为`QAudioRecorder`对象配置输入源，您需要将音频输入的名称传递给`setAudioInput()`方法，如下所示：

```py
        self.recorder.setAudioInput('default:')
```

输入的实际名称可能在您的系统上有所不同。不幸的是，当您设置无效的音频输入时，`QAudioRecorder`不会抛出异常或注册错误，它只是简单地无法录制任何音频。因此，如果决定自定义此属性，请务必确保该值首先是有效的。

要更改记录的输出文件，我们需要调用`setOutputLocation()`，如下所示：

```py
        sample_path = qtc.QDir.home().filePath('sample1')
        self.recorder.setOutputLocation(
            qtc.QUrl.fromLocalFile(sample_path))
```

请注意，`setOutputLocation()`需要一个`QUrl`对象，而不是文件路径。一旦设置，Qt 将尝试使用此位置来录制音频。但是，如前所述，如果此位置不可用，它将恢复到特定于平台的默认值。

容器格式是保存音频数据的文件类型。例如，`audio/x-wav`是用于 WAV 文件的容器。我们可以使用`setContainerFormat()`方法在记录对象中设置此值，如下所示：

```py
        self.recorder.setContainerFormat('audio/x-wav')
```

此属性的值应为`QAudioRecorder.supportedContainers()`返回的字符串。使用无效值将在您尝试录制时导致错误。

设置编解码器、采样率和质量需要一个称为`QAudioEncoderSettings`对象的新对象。以下示例演示了如何创建和配置`settings`对象：

```py
        settings = qtmm.QAudioEncoderSettings()
        settings.setCodec('audio/pcm')
        settings.setSampleRate(44100)
        settings.setQuality(qtmm.QMultimedia.HighQuality)
        self.recorder.setEncodingSettings(settings)
```

在这种情况下，我们已经将我们的音频配置为使用 PCM 编解码器以`44100` Hz 进行高质量编码。

请注意，并非所有编解码器都与所有容器类型兼容。如果选择了两种不兼容的类型，Qt 将在控制台上打印错误并且录制将失败，但不会崩溃或抛出异常。您需要进行适当的研究和测试，以确保您选择了兼容的设置。

根据所选择的编解码器，您可以在`QAudioEncoderSettings`对象上设置其他设置。您可以在[`doc.qt.io/qt-5/qaudioencodersettings.html`](https://doc.qt.io/qt-5/qaudioencodersettings.html)的 Qt 文档中查阅更多信息。

配置音频设置可能非常棘手，特别是因为支持在各个系统之间差异很大。最好在可以的时候让 Qt 使用其默认设置，或者让用户使用从`QAudioRecorder`的支持检测方法获得的值来配置这些设置。无论您做什么，如果您不能保证运行您的软件的系统将支持它们，请不要硬编码设置或选项。

# 录制和播放视频

一旦您了解了如何在 Qt 中处理音频，处理视频只是在复杂性方面迈出了一小步。就像处理音频一样，我们将使用一个播放器对象来加载和播放内容，以及一个记录器对象来记录它。但是，对于视频，我们需要添加一些额外的组件来处理内容的可视化并初始化源设备。

为了理解它是如何工作的，我们将构建一个视频日志应用程序。将应用程序模板从第四章 *使用 QMainWindow 构建应用程序*复制到一个名为`captains_log.py`的新文件中，然后我们将开始编码。

# 构建基本 GUI

**船长的日志**应用程序将允许我们从网络摄像头录制视频到一个预设目录中的时间戳文件，并进行回放。我们的界面将在右侧显示过去日志的列表，在左侧显示预览/回放区域。我们将有一个分页式界面，以便用户可以在回放和录制模式之间切换。

在`MainWindow.__init__()`中，按照以下方式开始布局基本 GUI：

```py
        base_widget = qtw.QWidget()
        base_widget.setLayout(qtw.QHBoxLayout())
        notebook = qtw.QTabWidget()
        base_widget.layout().addWidget(notebook)
        self.file_list = qtw.QListWidget()
        base_widget.layout().addWidget(self.file_list)
        self.setCentralWidget(base_widget)
```

接下来，我们将添加一个工具栏来容纳传输控件：

```py
        toolbar = self.addToolBar("Transport")
        record_act = toolbar.addAction('Rec')
        stop_act = toolbar.addAction('Stop')
        play_act = toolbar.addAction('Play')
        pause_act = toolbar.addAction('Pause')
```

我们希望我们的应用程序只显示日志视频，因此我们需要将我们的记录隔离到一个独特的目录，而不是使用记录的默认位置。使用`QtCore.QDir`，我们将以跨平台的方式创建和存储一个自定义位置，如下所示：

```py
        self.video_dir = qtc.QDir.home()
        if not self.video_dir.cd('captains_log'):
            qtc.QDir.home().mkdir('captains_log')
            self.video_dir.cd('captains_log')
```

这将在您的主目录下创建`captains_log`目录（如果不存在），并将`self.video_dir`对象设置为指向该目录。

我们现在需要一种方法来扫描这个目录以查找视频并填充列表小部件：

```py
    def refresh_video_list(self):
        self.file_list.clear()
        video_files = self.video_dir.entryList(
            ["*.ogg", "*.avi", "*.mov", "*.mp4", "*.mkv"],
            qtc.QDir.Files | qtc.QDir.Readable
        )
        for fn in sorted(video_files):
            self.file_list.addItem(fn)
```

`QDir.entryList()`返回我们的`video_dir`内容的列表。第一个参数是常见视频文件类型的过滤器列表，以便非视频文件不会在我们的日志列表中列出（可以随意添加您的操作系统喜欢的任何格式），第二个是一组标志，将限制返回的条目为可读文件。检索到这些文件后，它们将被排序并添加到列表小部件中。

回到`__init__()`，让我们调用这个函数来刷新列表：

```py
        self.refresh_video_list()
```

您可能希望在该目录中放入一个或两个视频文件，以确保它们被读取并添加到列表小部件中。

# 视频播放

我们的老朋友`QMediaPlayer`可以处理视频播放以及音频。但是，就像蓝光播放器需要连接到电视或监视器来显示它正在播放的内容一样，`QMediaPlayer`需要连接到一个实际显示视频的小部件。我们需要的小部件是`QVideoWidget`类，它位于`QtMultimediaWidgets`模块中。

要使用它，我们需要导入`QMultimediaWidgets`，如下所示：

```py
from PyQt5 import QtMultimediaWidgets as qtmmw
```

要将我们的`QMediaPlayer()`方法连接到`QVideoWidget()`方法，我们设置播放器的`videoOutput`属性，如下所示：

```py
        self.player = qtmm.QMediaPlayer()
        self.video_widget = qtmmw.QVideoWidget()
        self.player.setVideoOutput(self.video_widget)
```

这比连接蓝光播放器要容易，对吧？

现在我们可以将视频小部件添加到我们的 GUI，并将传输连接到我们的播放器：

```py
        notebook.addTab(self.video_widget, "Play")
        play_act.triggered.connect(self.player.play)
        pause_act.triggered.connect(self.player.pause)
        stop_act.triggered.connect(self.player.stop)
        play_act.triggered.connect(
            lambda: notebook.setCurrentWidget(self.video_widget))
```

最后，我们添加了一个连接，以便在单击播放按钮时切换回播放选项卡。

启用播放的最后一件事是将文件列表中的文件选择连接到加载和播放媒体播放器中的视频。

我们将在一个名为`on_file_selected()`的回调中执行此操作，如下所示：

```py
    def on_file_selected(self, item):
        fn = item.text()
        url = qtc.QUrl.fromLocalFile(self.video_dir.filePath(fn))
        content = qtmm.QMediaContent(url)
        self.player.setMedia(content)
        self.player.play()
```

回调函数从`file_list`接收`QListWidgetItem`并提取`text`参数，这应该是文件的名称。我们将其传递给我们的`QDir`对象的`filePath()`方法，以获得文件的完整路径，并从中构建一个`QUrl`对象（请记住，`QMediaPlayer`使用 URL 而不是文件路径）。最后，我们将内容包装在`QMediaContent`对象中，将其加载到播放器中，并点击`play()`。

回到`__init__()`，让我们将此回调连接到我们的列表小部件：

```py
        self.file_list.itemDoubleClicked.connect(
            self.on_file_selected)
        self.file_list.itemDoubleClicked.connect(
            lambda: notebook.setCurrentWidget(self.video_widget))
```

在这里，我们连接了`itemDoubleClicked`，它将被点击的项目传递给槽，就像我们的回调所期望的那样。请注意，我们还将该操作连接到一个`lambda`函数，以切换到视频小部件。这样，如果用户在录制选项卡上双击文件，他们将能够在不手动切换回播放选项卡的情况下观看它。

此时，您的播放器已经可以播放视频。如果您还没有在`captains_log`目录中放入一些视频文件，请放入一些并查看它们是否可以播放。

# 视频录制

要录制视频，我们首先需要一个来源。在 Qt 中，此来源必须是`QMediaObject`的子类，其中可以包括音频来源、媒体播放器、收音机，或者在本程序中将使用的相机。

Qt 5.12 目前不支持 Windows 上的视频录制，只支持 macOS 和 Linux。有关 Windows 上多媒体支持当前状态的更多信息，请参阅[`doc.qt.io/qt-5/qtmultimedia-windows.html`](https://doc.qt.io/qt-5/qtmultimedia-windows.html)。

在 Qt 中，相机本身表示为`QCamera`对象。要创建一个可工作的`QCamera`对象，我们首先需要获取一个`QCameraInfo`对象。`QCameraInfo`对象包含有关连接到计算机的物理相机的信息。可以从`QtMultimedia.QCameraInfo.availableCameras()`方法获取这些对象的列表。

让我们将这些放在一起，形成一个方法，该方法将在您的系统上查找相机并返回一个`QCamera`对象：

```py
    def camera_check(self):
        cameras = qtmm.QCameraInfo.availableCameras()
        if not cameras:
            qtw.QMessageBox.critical(
                self,
                'No cameras',
                'No cameras were found, recording disabled.'
            )
        else:
            return qtmm.QCamera(cameras[0])
```

如果您的系统连接了一个或多个相机，`availableCameras()`应该返回一个`QCameraInfo`对象的列表。如果没有，那么我们将显示一个错误并返回空；如果有，那么我们将信息对象传递给`QCamera`构造函数，并返回表示相机的对象。

回到`__init__()`，我们将使用以下函数来获取相机对象：

```py
        self.camera = self.camera_check()
        if not self.camera:
            self.show()
            return
```

如果没有相机，那么此方法中剩余的代码将无法工作，因此我们将只显示窗口并返回。

在使用相机之前，我们需要告诉它我们希望它捕捉什么。相机可以捕捉静态图像或视频内容，这由相机的`captureMode`属性配置。

在这里，我们将其设置为视频，使用`QCamera.CaptureVideo`常量：

```py
        self.camera.setCaptureMode(qtmm.QCamera.CaptureVideo)
```

在我们开始录制之前，我们希望能够预览相机捕捉的内容（毕竟，船长需要确保他们的头发看起来很好以供后人纪念）。`QtMultimediaWidgets`有一个专门用于此目的的特殊小部件，称为`QCameraViewfinder`。

我们将添加一个并将我们的相机连接到它，如下所示：

```py
        self.cvf = qtmmw.QCameraViewfinder()
        self.camera.setViewfinder(self.cvf)
        notebook.addTab(self.cvf, 'Record')
```

相机现在已经创建并配置好了，所以我们需要通过调用`start()`方法来激活它：

```py
        self.camera.start()
```

如果您此时运行程序，您应该在录制选项卡上看到相机捕捉的实时显示。

这个谜题的最后一块是录制器对象。在视频的情况下，我们使用`QMediaRecorder`类来创建一个视频录制对象。这个类实际上是我们在声音板中使用的`QAudioRecorder`类的父类，并且工作方式基本相同。

让我们创建我们的录制器对象，如下所示：

```py
        self.recorder = qtmm.QMediaRecorder(self.camera)
```

请注意，我们将摄像头对象传递给构造函数。每当创建`QMediaRecorder`属性时，必须传递`QMediaObject`（其中`QCamera`是子类）。此属性不能以后设置，也不能在没有它的情况下调用构造函数。

就像我们的音频录制器一样，我们可以配置有关我们捕获的视频的各种设置。这是通过创建一个`QVideoEncoderSettings`类并将其传递给录制器的`videoSettings`属性来完成的：

```py
        settings = self.recorder.videoSettings()
        settings.setResolution(640, 480)
        settings.setFrameRate(24.0)
        settings.setQuality(qtmm.QMultimedia.VeryHighQuality)
        self.recorder.setVideoSettings(settings)
```

重要的是要理解，如果你设置了你的摄像头不支持的配置，那么录制很可能会失败，你可能会在控制台看到错误：

```py
CameraBin warning: "not negotiated"
CameraBin error: "Internal data stream error."
```

为了确保这不会发生，我们可以查询我们的录制对象，看看支持哪些设置，就像我们对音频设置所做的那样。以下脚本将打印每个检测到的摄像头在您的系统上支持的编解码器、帧速率、分辨率和容器到控制台：

```py
from PyQt5.QtCore import *
from PyQt5.QtMultimedia import *

app = QCoreApplication([])

for camera_info in QCameraInfo.availableCameras():
    print('Camera: ', camera_info.deviceName())
    camera = QCamera(camera_info)
    r = QMediaRecorder(camera)
    print('\tAudio Codecs: ', r.supportedAudioCodecs())
    print('\tVideo Codecs: ', r.supportedVideoCodecs())
    print('\tAudio Sample Rates: ', r.supportedAudioSampleRates())
    print('\tFrame Rates: ', r.supportedFrameRates())
    print('\tResolutions: ', r.supportedResolutions())
    print('\tContainers: ', r.supportedContainers())
    print('\n\n')
```

请记住，在某些系统上，返回的结果可能为空。如果有疑问，最好要么进行实验，要么接受默认设置提供的任何内容。

现在我们的录制器已经准备好了，我们需要连接传输并启用它进行录制。让我们首先编写一个用于录制的回调方法：

```py
    def record(self):
        # create a filename
        datestamp = qtc.QDateTime.currentDateTime().toString()
        self.mediafile = qtc.QUrl.fromLocalFile(
            self.video_dir.filePath('log - ' + datestamp)
        )
        self.recorder.setOutputLocation(self.mediafile)
        # start recording
        self.recorder.record()
```

这个回调有两个作用——创建并设置要记录的文件名，并开始录制。我们再次使用我们的`QDir`对象，结合`QDateTime`类来生成包含按下记录时的日期和时间的文件名。请注意，我们不向文件名添加文件扩展名。这是因为`QMediaRecorder`将根据其配置为创建的文件类型自动执行此操作。

通过简单调用`QMediaRecorder`对象上的`record()`来启动录制。它将在后台记录视频，直到调用`stop()`插槽。

回到`__init__()`，让我们通过以下方式完成连接传输控件：

```py
        record_act.triggered.connect(self.record)
        record_act.triggered.connect(
            lambda: notebook.setCurrentWidget(self.cvf)
        )
        pause_act.triggered.connect(self.recorder.pause)
        stop_act.triggered.connect(self.recorder.stop)
        stop_act.triggered.connect(self.refresh_video_list)
```

我们将记录操作连接到我们的回调和一个 lambda 函数，该函数切换到录制选项卡。然后，我们直接将暂停和停止操作连接到录制器的`pause()`和`stop()`插槽。最后，当视频停止录制时，我们将希望刷新文件列表以显示新文件，因此我们将`stop_act`连接到`refresh_video_list()`回调。

这就是我们需要的一切；擦拭一下你的网络摄像头镜头，启动这个脚本，开始跟踪你的星际日期！

# 总结

在本章中，我们探索了`QtMultimedia`和`QMultimediaWidgets`模块的功能。您学会了如何使用`QSoundEffect`播放低延迟音效，以及如何使用`QMediaPlayer`和`QAudioRecorder`播放和记录各种媒体格式。最后，我们使用`QCamera`、`QMediaPlayer`和`QMediaRecorder`创建了一个视频录制和播放应用程序。

在下一章中，我们将通过探索 Qt 的网络功能来连接到更广泛的世界。我们将使用套接字进行低级网络和使用`QNetworkAccessManager`进行高级网络。

# 问题

尝试这些问题来测试你从本章学到的知识：

1.  使用`QSoundEffect`，你为呼叫中心编写了一个实用程序，允许他们回顾录制的电话呼叫。他们正在转移到一个将音频呼叫存储为 MP3 文件的新电话系统。你需要对你的实用程序进行任何更改吗？

1.  `cool_songs`是一个包含你最喜欢的歌曲路径字符串的 Python 列表。要以随机顺序播放这些歌曲，你需要做什么？

1.  你已经在你的系统上安装了`audio/mpeg`编解码器，但以下代码不起作用。找出问题所在：

```py
   recorder = qtmm.QAudioRecorder()
   recorder.setCodec('audio/mpeg')
   recorder.record()
```

1.  在几个不同的 Windows、macOS 和 Linux 系统上运行`audio_test.py`和`video_test.py`。输出有什么不同？有哪些项目在所有系统上都受支持？

1.  `QCamera`类的属性包括几个控制对象，允许您管理相机的不同方面。其中之一是`QCameraFocus`。在 Qt 文档中调查`QCameraFocus`，网址为[`doc.qt.io/qt-5/qcamerafocus.html`](https://doc.qt.io/qt-5/qcamerafocus.html)，并编写一个简单的脚本，显示取景器并让您调整数字变焦。

1.  您注意到录制到您的**船长日志**视频日志中的音频相当响亮。您想添加一个控件来调整它；您会如何做？

1.  在`captains_log.py`中实现一个停靠窗口小部件，允许您控制尽可能多的音频和视频录制方面。您可以包括焦点、变焦、曝光、白平衡、帧速率、分辨率、音频音量、音频质量等内容。

# 进一步阅读

您可以查阅以下参考资料以获取更多信息：

+   您可以在[`doc.qt.io/qt-5/multimediaoverview.html`](https://doc.qt.io/qt-5/multimediaoverview.html)上了解 Qt 多媒体系统及其功能。

+   PyQt 的官方`QtMultimedia`和`QtMultimediaWidgets`示例可以在[`github.com/pyqt/examples/tree/master/multimedia`](https://github.com/pyqt/examples/tree/master/multimedia)和[`github.com/pyqt/examples/tree/master/multimediawidgets`](https://github.com/pyqt/examples/tree/master/multimediawidgets)找到。它们提供了更多使用 PyQt 进行媒体捕获和播放的示例代码。


# 第八章：使用 QtNetwork 进行网络连接

人类是社会性动物，越来越多的软件系统也是如此。尽管计算机本身很有用，但与其他计算机连接后，它们的用途要大得多。无论是在小型本地交换机还是全球互联网上，通过网络与其他系统进行交互对于大多数现代软件来说都是至关重要的功能。在本章中，我们将探讨 Qt 提供的网络功能以及如何在 PyQt5 中使用它们。

特别是，我们将涵盖以下主题：

+   使用套接字进行低级网络连接

+   使用`QNetworkAccessManager`进行 HTTP 通信

# 技术要求

与其他章节一样，您需要一个基本的 Python 和 PyQt5 设置，如第一章中所述，并且您将受益于从我们的 GitHub 存储库下载示例代码[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter08`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter08)。

此外，您将希望至少有另一台装有 Python 的计算机连接到同一局域网。

查看以下视频以查看代码的运行情况：[`bit.ly/2M5xqid`](http://bit.ly/2M5xqid)

# 使用套接字进行低级网络连接

几乎每个现代网络都使用**互联网协议套件**，也称为**TCP/IP**，来促进计算机或其他设备之间的连接。TCP/IP 是一组管理网络上原始数据传输的协议。直接在代码中使用 TCP/IP 最常见的方法是使用**套接字 API**。

套接字是一个类似文件的对象，代表系统的网络连接点。每个套接字都有一个**主机地址**，**网络端口**和**传输协议**。

主机地址，也称为**IP 地址**，是用于在网络上标识单个网络主机的一组数字。尽管骨干系统依赖 IPv6 协议，但大多数个人计算机仍使用较旧的 IPv4 地址，该地址由点分隔的四个介于`0`和`255`之间的数字组成。您可以使用 GUI 工具找到系统的地址，或者通过在命令行终端中键入以下命令之一来找到地址：

| OS | Command |
| --- | --- |
| Windows | `ipconfig` |  |
| macOS | `ifconfig` |
| Linux | `ip address` |  |

端口只是一个从`0`到`65535`的数字。虽然您可以使用任何端口号创建套接字，但某些端口号分配给常见服务；这些被称为**众所周知的端口**。例如，HTTP 服务器通常分配到端口`80`，SSH 通常在端口`22`上。在许多操作系统上，需要管理或根权限才能在小于`1024`的端口上创建套接字。

可以在[`www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml`](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)找到官方的众所周知的端口列表。

传输协议包括**传输控制协议**（**TCP**）和**用户数据报协议**（**UDP**）。TCP 是两个系统之间的有状态连接。您可以将其视为电话呼叫 - 建立连接，交换信息，并在某个明确的点断开连接。由于其有状态性，TCP 确保接收所有传输的数据包。另一方面，UDP 是一种无状态协议。将其视为使用对讲机 - 用户传输消息，接收者可能完整或部分接收，且不会建立明确的连接。UDP 相对轻量级，通常用于广播消息，因为它不需要与特定主机建立连接。

`QtNetwork`模块为我们提供了建立 TCP 和 UDP 套接字连接的类。为了理解它们的工作原理，我们将构建两个聊天系统 - 一个使用 UDP，另一个使用 TCP。

# 构建聊天 GUI

让我们首先创建一个基本的 GUI 表单，我们可以在聊天应用的两个版本中使用。从第四章的应用程序模板开始，*使用 QMainWindow 构建应用程序*，然后添加这个类：

```py
class ChatWindow(qtw.QWidget):

    submitted = qtc.pyqtSignal(str)

    def __init__(self):
        super().__init__()

        self.setLayout(qtw.QGridLayout())
        self.message_view = qtw.QTextEdit(readOnly=True)
        self.layout().addWidget(self.message_view, 1, 1, 1, 2)
        self.message_entry = qtw.QLineEdit()
        self.layout().addWidget(self.message_entry, 2, 1)
        self.send_btn = qtw.QPushButton('Send', clicked=self.send)
        self.layout().addWidget(self.send_btn, 2, 2)
```

GUI 很简单，只有一个文本编辑器来显示对话，一个行编辑器来输入消息，以及一个发送按钮。我们还实现了一个信号，每当用户提交新消息时就可以发出。

GUI 还将有两个方法：

```py
    def write_message(self, username, message):
        self.message_view.append(f'<b>{username}: </b> {message}<br>')

    def send(self):
        message = self.message_entry.text().strip()
        if message:
            self.submitted.emit(message)
            self.message_entry.clear()
```

`send()` 方法由 `send_btn` 按钮触发，发出包含行编辑中文本的 `submitted` 信号，以及 `write_message()` 方法，该方法接收 `username` 和 `message` 并使用一些简单的格式将其写入文本编辑器。

在 `MainWindow.__init__()` 方法中，添加以下代码：

```py
        self.cw = ChatWindow()
        self.setCentralWidget(self.cw)
```

最后，在我们可以进行任何网络编码之前，我们需要为 `QtNetwork` 添加一个 `import`。像这样将其添加到文件的顶部：

```py
from PyQt5 import QtNetwork as qtn
```

这段代码将是我们的 UDP 和 TCP 聊天应用程序的基础代码，所以将这个文件保存为 `udp_chat.py` 的一个副本，另一个副本保存为 `tcp_chat.py`。我们将通过为表单创建一个后端对象来完成每个应用程序。

# 构建 UDP 聊天客户端

UDP 最常用于本地网络上的广播应用程序，因此为了演示这一点，我们将使我们的 UDP 聊天成为一个仅限本地网络的广播聊天。这意味着在运行此应用程序副本的本地网络上的任何计算机都将能够查看并参与对话。

我们将首先创建我们的后端类，我们将其称为 `UdpChatInterface`：

```py
class UdpChatInterface(qtc.QObject):

    port = 7777
    delimiter = '||'
    received = qtc.pyqtSignal(str, str)
    error = qtc.pyqtSignal(str)
```

我们的后端继承自 `QObject`，以便我们可以使用 Qt 信号，我们定义了两个信号——一个 `received` 信号，当接收到消息时我们将发出它，一个 `error` 信号，当发生错误时我们将发出它。我们还定义了一个要使用的端口号和一个 `delimiter` 字符串。当我们序列化消息进行传输时，`delimiter` 字符串将用于分隔用户名和消息；因此，当用户 `alanm` 发送消息 `Hello World` 时，我们的接口将在网络上发送字符串 `alanm||Hello World`。

一次只能将一个应用程序绑定到一个端口；如果您已经有一个使用端口 `7777` 的应用程序，您应该将这个数字更改为 `1024` 到 `65535` 之间的其他数字。在 Windows、macOS 和旧版 Linux 系统上，可以使用 `netstat` 命令来显示正在使用哪些端口。在较新的 Linux 系统上，可以使用 `ss` 命令。

现在开始一个 `__init__()` 方法：

```py
    def __init__(self, username):
        super().__init__()
        self.username = username

        self.socket = qtn.QUdpSocket()
        self.socket.bind(qtn.QHostAddress.Any, self.port)
```

调用 `super()` 并存储 `username` 变量后，我们的首要任务是创建和配置一个 `QUdpSocket` 对象。在我们可以使用套接字之前，它必须**绑定**到本地主机地址和端口号。`QtNetwork.QHostAddress.Any` 表示本地系统上的所有地址，因此我们的套接字将在所有本地接口上监听和发送端口 `7777` 上的数据。

要使用套接字，我们必须处理它的信号：

```py
        self.socket.readyRead.connect(self.process_datagrams)
        self.socket.error.connect(self.on_error)
```

Socket 对象有两个我们感兴趣的信号。第一个是 `readyRead`，每当套接字接收到数据时就会发出该信号。我们将在一个名为 `process_datagrams()` 的方法中处理该信号，我们马上就会写这个方法。

`error` 信号在发生任何错误时发出，我们将在一个名为 `on_error()` 的实例方法中处理它。

让我们从错误处理程序开始，因为它相对简单：

```py
    def on_error(self, socket_error):
        error_index = (qtn.QAbstractSocket
                       .staticMetaObject
                       .indexOfEnumerator('SocketError'))
        error = (qtn.QAbstractSocket
                 .staticMetaObject
                 .enumerator(error_index)
                 .valueToKey(socket_error))
        message = f"There was a network error: {error}"
        self.error.emit(message)
```

这种方法在其中有一点 Qt 的魔力。网络错误在`QAbstractSocket`类（`UdpSocket`的父类）的`SocketError`枚举中定义。不幸的是，如果我们只是尝试打印错误，我们会得到常量的整数值。要实际获得有意义的字符串，我们将深入与`QAbstractSocket`关联的`staticMetaObject`。我们首先获取包含错误常量的枚举类的索引，然后使用`valueToKey()`将我们的套接字错误整数转换为其常量名称。这个技巧可以用于任何 Qt 枚举，以检索有意义的名称而不仅仅是它的整数值。

一旦被检索，我们只需将错误格式化为消息并在我们的`error`信号中发出。

现在让我们来解决`process_datagrams()`：

```py
    def process_datagrams(self):
        while self.socket.hasPendingDatagrams():
            datagram = self.socket.receiveDatagram()
            raw_message = bytes(datagram.data()).decode('utf-8')
```

单个 UDP 传输被称为**数据报**。当我们的套接字接收到数据报时，它被存储在缓冲区中，并发出`readyRead`信号。只要该缓冲区有等待的数据报，套接字的`hasPendingDatagrams()`将返回`True`。因此，只要有待处理的数据报，我们就会循环调用套接字的`receiveDatagram()`方法，该方法返回并移除缓冲区中等待的下一个数据报，直到检索到所有数据报为止。

`receiveDatagram()`返回的数据报对象是`QByteArray`，相当于 Python 的`bytes`对象。由于我们的程序传输的是字符串，而不是二进制对象，我们可以将`QByteArray`直接转换为 Unicode 字符串。这样做的最快方法是首先将其转换为`bytes`对象，然后使用`decode()`方法将其转换为 UTF-8 Unicode 文本。

现在我们有了原始字符串，我们需要检查它以确保它来自`udp_chat.py`的另一个实例，然后将其拆分成`username`和`message`组件：

```py
            if self.delimiter not in raw_message:
                continue
            username, message = raw_message.split(self.delimiter, 1)
            self.received.emit(username, message)
```

如果套接字接收到的原始文本不包含我们的`delimiter`字符串，那么它很可能来自其他程序或损坏的数据包，我们将跳过它。否则，我们将在第一个`delimiter`的实例处将其拆分为`username`和`message`字符串，然后发出这些字符串与`received`信号。

我们的聊天客户端需要的最后一件事是发送消息的方法，我们将在`send_message()`方法中实现：

```py
   def send_message(self, message):
        msg_bytes = (
            f'{self.username}{self.delimiter}{message}'
        ).encode('utf-8')
        self.socket.writeDatagram(
            qtc.QByteArray(msg_bytes),
            qtn.QHostAddress.Broadcast,
            self.port
        )
```

这种方法首先通过使用`delimiter`字符串格式化传递的消息与我们配置的用户名，然后将格式化的字符串编码为`bytes`对象。

接下来，我们使用`writeDatagram()`方法将数据报写入我们的套接字对象。这个方法接受一个`QByteArray`（我们已经将我们的`bytes`对象转换为它）和一个目标地址和端口。我们的目的地被指定为`QHostAddress.Broadcast`，这表示我们要使用广播地址，端口当然是我们在类变量中定义的端口。

**广播地址**是 TCP/IP 网络上的保留地址，当使用时，表示传输应该被所有主机接收。

让我们总结一下我们在这个后端中所做的事情：

+   发送消息时，消息将以用户名为前缀，并作为字节数组广播到网络上的所有主机的端口`7777`。

+   当在端口`7777`上接收到消息时，它将从字节数组转换为字符串。消息和用户名被拆分并发出信号。

+   发生错误时，错误号将被转换为错误字符串，并与错误信号一起发出。

现在我们只需要将我们的后端连接到前端表单。

# 连接信号

回到我们的`MainWindow`构造函数，我们需要通过创建一个`UdpChatInterface`对象并连接其信号来完成我们的应用程序：

```py
        username = qtc.QDir.home().dirName()
        self.interface = UdpChatInterface(username)
        self.cw.submitted.connect(self.interface.send_message)
        self.interface.received.connect(self.cw.write_message)
        self.interface.error.connect(
            lambda x: qtw.QMessageBox.critical(None, 'Error', x))
```

在创建界面之前，我们通过获取当前用户的主目录名称来确定`username`。这有点像黑客，但对我们的目的来说足够好了。

接下来，我们创建我们的接口对象，并将聊天窗口的`submitted`信号连接到其`send_message()`槽。

然后，我们将接口的`received`信号连接到聊天窗口的`write_message()`方法，将`error`信号连接到一个 lambda 函数，用于在`QMessageBox`中显示错误。

一切都连接好了，我们准备好测试了。

# 测试聊天

要测试这个聊天系统，您需要两台安装了 Python 和 PyQt5 的计算机，运行在同一个局域网上。在继续之前，您可能需要禁用系统的防火墙或打开 UDP 端口`7777`。

完成后，将`udp_chat.py`复制到两台计算机上并启动它。在一台计算机上输入一条消息；它应该会显示在两台计算机的聊天窗口中，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/152c38db-31b6-4c6a-b19e-beea931a4787.png)

请注意，系统也会接收并对自己的广播消息做出反应，因此我们不需要担心在文本区域中回显自己的消息。

UDP 确实很容易使用，但它有许多限制。例如，UDP 广播通常无法路由到本地网络之外，而且无状态连接的缺失意味着无法知道传输是否已接收或丢失。在*构建 TCP 聊天客户端*部分，我们将构建一个没有这些问题的聊天 TCP 版本。

# 构建 TCP 聊天客户端

TCP 是一种有状态的传输协议，这意味着建立并维护连接直到传输完成。TCP 也主要是一对一的主机连接，我们通常使用**客户端-服务器**设计来实现。我们的 TCP 聊天应用程序将在两个网络主机之间建立直接连接，并包含一个客户端组件，用于连接应用程序的其他实例，以及一个服务器组件，用于处理传入的客户端连接。

在您之前创建的`tcp_chat.py`文件中，像这样启动一个 TCP 聊天接口类：

```py
class TcpChatInterface(qtc.QObject):

    port = 7777
    delimiter = '||'
    received = qtc.pyqtSignal(str, str)
    error = qtc.pyqtSignal(str)
```

到目前为止，这与 UDP 接口完全相同，除了名称。现在让我们创建构造函数：

```py
    def __init__(self, username, recipient):
        super().__init__()
        self.username = username
        self.recipient = recipient
```

与以前一样，接口对象需要一个`username`，但我们还添加了一个`recipient`参数。由于 TCP 需要与另一个主机建立直接连接，我们需要指定要连接的远程主机。

现在我们需要创建服务器组件，用于监听传入的连接：

```py
        self.listener = qtn.QTcpServer()
        self.listener.listen(qtn.QHostAddress.Any, self.port)
        self.listener.acceptError.connect(self.on_error)

        self.listener.newConnection.connect(self.on_connection)
        self.connections = []
```

`listener`是一个`QTcpServer`对象。`QTcpServer`使我们的接口能够在给定接口和端口上接收来自 TCP 客户端的传入连接，这里我们将其设置为端口`7777`上的任何本地接口。

当有传入连接出现错误时，服务器对象会发出一个`acceptError`信号，我们将其连接到一个`on_error()`方法。这些是`UdpSocket`发出的相同类型的错误，因此我们可以从`udp_chat.py`中复制`on_error()`方法并以相同的方式处理它们。

每当有新连接进入服务器时，都会发出`newConnection`信号；我们将在一个名为`on_connection()`的方法中处理这个信号，它看起来像这样：

```py
    def on_connection(self):
        connection = self.listener.nextPendingConnection()
        connection.readyRead.connect(self.process_datastream)
        self.connections.append(connection)
```

服务器的`nextPendingConnection()`方法返回一个`QTcpSocket`对象作为下一个等待连接。像`QUdpSocket`一样，`QTcpSocket`在接收数据时会发出`readyRead`信号。我们将把这个信号连接到一个`process_datastream()`方法。

最后，我们将在`self.connections`列表中保存对新连接的引用。

# 处理数据流

虽然 UDP 套接字使用数据报，但 TCP 套接字使用**数据流**。顾名思义，数据流涉及数据的流动而不是离散的单元。TCP 传输被发送为一系列网络数据包，这些数据包可能按照正确的顺序到达，也可能不会，接收方需要正确地重新组装接收到的数据。为了使这个过程更容易，我们可以将套接字包装在一个`QtCore.QDataStream`对象中，它提供了一个从类似文件的源读取和写入数据的通用接口。

让我们像这样开始我们的方法：

```py
    def process_datastream(self):
        for socket in self.connections:
            self.datastream = qtc.QDataStream(socket)
            if not socket.bytesAvailable():
                continue
```

我们正在遍历连接的套接字，并将每个传递给`QDataStream`对象。`socket`对象有一个`bytesAvailable()`方法，告诉我们有多少字节的数据排队等待读取。如果这个数字为零，我们将继续到列表中的下一个连接。

如果没有，我们将从数据流中读取：

```py
            raw_message = self.datastream.readQString()
            if raw_message and self.delimiter in raw_message:
                username, message = raw_message.split(self.delimiter, 1)
                self.received.emit(username, message)
```

`QDataStream.readQString()`尝试从数据流中提取一个字符串并返回它。尽管名称如此，在 PyQt5 中，这个方法实际上返回一个 Python Unicode 字符串，而不是`QString`。重要的是要理解，这个方法*只有*在原始数据包中发送了`QString`时才起作用。如果发送了其他对象（原始字节字符串、整数等），`readQString()`将返回`None`。

`QDataStream`有用于写入和读取各种数据类型的方法。请参阅其文档[`doc.qt.io/qt-5/qdatastream.html`](https://doc.qt.io/qt-5/qdatastream.html)。

一旦我们将传输作为字符串，我们将检查原始消息中的`delimiter`字符串，并且如果找到，拆分原始消息并发出`received`信号。

# 通过 TCP 发送数据

`QTcpServer`已经处理了消息的接收；现在我们需要实现发送消息。为此，我们首先需要创建一个`QTcpSocket`对象作为我们的客户端套接字。

让我们将其添加到`__init__()`的末尾：

```py
        self.client_socket = qtn.QTcpSocket()
        self.client_socket.error.connect(self.on_error)
```

我们创建了一个默认的`QTcpSocket`对象，并将其`error`信号连接到我们的错误处理方法。请注意，我们不需要绑定此套接字，因为它不会监听。

为了使用客户端套接字，我们将创建一个`send_message()`方法；就像我们的 UDP 聊天一样，这个方法将首先将消息格式化为原始传输字符串：

```py
    def send_message(self, message):
        raw_message = f'{self.username}{self.delimiter}{message}'
```

现在我们需要连接到要通信的远程主机：

```py
    socket_state = self.client_socket.state()
    if socket_state != qtn.QAbstractSocket.ConnectedState:
        self.client_socket.connectToHost(
            self.recipient, self.port)
```

套接字的`state`属性可以告诉我们套接字是否连接到远程主机。`QAbstractSocket.ConnectedState`状态表示我们的客户端已连接到服务器。如果没有，我们调用套接字的`connectToHost()`方法来建立与接收主机的连接。

现在我们可以相当肯定我们已经连接了，让我们发送消息。为了做到这一点，我们再次转向`QDataStream`对象来处理与我们的 TCP 套接字通信的细节。

首先创建一个附加到客户端套接字的新数据流：

```py
        self.datastream = qtc.QDataStream(self.client_socket)
```

现在我们可以使用`writeQString()`方法向数据流写入字符串：

```py
        self.datastream.writeQString(raw_message)
```

重要的是要理解，对象只能按照我们发送它们的顺序从数据流中提取。例如，如果我们想要在字符串前面加上它的长度，以便接收方可以检查它是否损坏，我们可以这样做：

```py
        self.datastream.writeUInt32(len(raw_message))
        self.datastream.writeQString(raw_message)
```

然后我们的`process_datastream()`方法需要相应地进行调整：

```py
    def process_datastream(self):
        #...
        message_length = self.datastream.readUInt32()
        raw_message = self.datastream.readQString()
```

在`send_message()`中我们需要做的最后一件事是本地发出我们的消息，以便本地显示可以显示它。由于这不是广播消息，我们的本地 TCP 服务器不会听到发送出去的消息。

在`send_message()`的末尾添加这个：

```py
        self.received.emit(self.username, message)
```

让我们总结一下这个后端的操作方式：

+   我们有一个 TCP 服务器组件：

+   TCP 服务器对象在端口`7777`上监听来自远程主机的连接

+   当接收到连接时，它将连接存储为套接字，并等待来自该套接字的数据

+   当接收到数据时，它将从套接字中读取数据流，解释并发出

+   我们有一个 TCP 客户端组件：

+   当需要发送消息时，首先对其进行格式化

+   然后检查连接状态，如果需要建立连接

+   一旦确保连接状态，消息将被写入套接字使用数据流

# 连接我们的后端并进行测试

回到`MainWindow.__init__()`，我们需要添加相关的代码来创建我们的接口并连接信号：

```py
        recipient, _ = qtw.QInputDialog.getText(
            None, 'Recipient',
            'Specify of the IP or hostname of the remote host.')
        if not recipient:
            sys.exit()

        self.interface = TcpChatInterface(username, recipient)
        self.cw.submitted.connect(self.interface.send_message)
        self.interface.received.connect(self.cw.write_message)
        self.interface.error.connect(
            lambda x: qtw.QMessageBox.critical(None, 'Error', x))
```

由于我们需要一个接收者，我们将使用`QInputDialog`询问用户。这个对话框类允许您轻松地查询用户的单个值。在这种情况下，我们要求输入另一个系统的 IP 地址或主机名。这个值我们传递给`TcpChatInterface`构造函数。

代码的其余部分基本上与 UDP 聊天客户端相同。

要测试这个聊天客户端，您需要在同一网络上的另一台计算机上运行一个副本，或者在您自己的网络中可以访问的地址上运行。当您启动客户端时，请指定另一台计算机的 IP 或主机名。一旦两个客户端都在运行，您应该能够互发消息。如果您在第三台计算机上启动客户端，请注意您将看不到消息，因为它们只被发送到单台计算机。

# 使用`QNetworkAccessManager`进行 HTTP 通信

**超文本传输协议**（**HTTP**）是构建万维网的协议，也可以说是我们这个时代最重要的通信协议。我们当然可以在套接字上实现自己的 HTTP 通信，但 Qt 已经为我们完成了这项工作。`QNetworkAccessManager`类实现了一个可以传输 HTTP 请求和接收 HTTP 回复的对象。我们可以使用这个类来创建与 Web 服务和 API 通信的应用程序。

# 简单下载

为了演示`QNetworkAccessManager`的基本用法，我们将构建一个简单的命令行 HTTP 下载工具。打开一个名为`downloader.py`的空文件，让我们从一些导入开始：

```py
import sys
from os import path
from PyQt5 import QtNetwork as qtn
from PyQt5 import QtCore as qtc
```

由于我们这里不需要`QtWidgets`或`QtGui`，只需要`QtNetwork`和`QtCore`。我们还将使用标准库`path`模块进行一些基于文件系统的操作。

让我们为我们的下载引擎创建一个`QObject`子类：

```py
class Downloader(qtc.QObject):

    def __init__(self, url):
        super().__init__()
        self.manager = qtn.QNetworkAccessManager(
            finished=self.on_finished)
        self.request = qtn.QNetworkRequest(qtc.QUrl(url))
        self.manager.get(self.request)
```

在我们的下载引擎中，我们创建了一个`QNetworkAccessManager`，并将其`finished`信号连接到一个名为`on_finish()`的回调函数。当管理器完成网络事务并准备好处理回复时，它会发出`finished`信号，并将回复包含在信号中。

接下来，我们创建一个`QNetworkRequest`对象。`QNetworkRequest`代表我们发送到远程服务器的 HTTP 请求，并包含我们要发送的所有信息。在这种情况下，我们只需要构造函数中传入的 URL。

最后，我们告诉我们的网络管理器使用`get()`执行请求。`get()`方法使用 HTTP `GET`方法发送我们的请求，通常用于请求下载的信息。管理器将发送这个请求并等待回复。

当回复到来时，它将被发送到我们的`on_finished()`回调函数：

```py
    def on_finished(self, reply):
        filename = reply.url().fileName() or 'download'
        if path.exists(filename):
            print('File already exists, not overwriting.')
            sys.exit(1)
        with open(filename, 'wb') as fh:
            fh.write(reply.readAll())
        print(f"{filename} written")
        sys.exit(0)
```

这里的`reply`对象是一个`QNetworkReply`实例，其中包含从远程服务器接收的数据和元数据。

我们首先尝试确定一个文件名，我们将用它来保存文件。回复的`url`属性包含原始请求所发出的 URL，我们可以查询 URL 的`fileName`属性。有时这是空的，所以我们将退而求其次使用`'download'`字符串。

接下来，我们将检查文件名是否已经存在于我们的系统上。出于安全考虑，如果存在，我们将退出，这样您就不会在测试这个演示时破坏重要文件。

最后，我们使用它的`readAll()`方法从回复中提取数据，并将这些数据写入本地文件。请注意，我们以`wb`模式（写入二进制）打开文件，因为`readAll()`以`QByteAarray`对象的形式返回二进制数据。

我们的`Downloader`类的主要执行代码最后出现：

```py
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <download url>')
        sys.exit(1)
    app = qtc.QCoreApplication(sys.argv)
    d = Downloader(sys.argv[1])
    sys.exit(app.exec_())
```

在这里，我们只是从命令行中获取第一个参数，并将其传递给我们的`Downloader`对象。请注意，我们使用的是`QCoreApplication`而不是`QApplication`；当您想要创建一个命令行 Qt 应用程序时，可以使用这个类。否则，它与`QApplication`是一样的。

简而言之，使用`QNetworkAccessManager`就是这么简单：

+   创建一个`QNetworkAccessManager`对象

+   创建一个`QNetworkRequest`对象

+   将请求传递给管理器的`get()`方法

+   在与管理器的`finished`信号连接的回调中处理回复

# 发布数据和文件

使用`GET`请求检索数据是相当简单的 HTTP；为了更深入地探索 PyQt5 的 HTTP 通信，我们将构建一个实用程序，允许我们向远程 URL 发送带有任意键值和文件数据的`POST`请求。例如，这个实用程序可能对测试 Web API 很有用。

# 构建 GUI

从第四章的 Qt 应用程序模板的副本开始，*使用 QMainWindow 构建应用程序*，让我们将主要的 GUI 代码添加到`MainWindow.__init__()`方法中：

```py
        widget = qtw.QWidget(minimumWidth=600)
        self.setCentralWidget(widget)
        widget.setLayout(qtw.QVBoxLayout())
        self.url = qtw.QLineEdit()
        self.table = qtw.QTableWidget(columnCount=2, rowCount=5)
        self.table.horizontalHeader().setSectionResizeMode(
            qtw.QHeaderView.Stretch)
        self.table.setHorizontalHeaderLabels(['key', 'value'])
        self.fname = qtw.QPushButton(
            '(No File)', clicked=self.on_file_btn)
        submit = qtw.QPushButton('Submit Post', clicked=self.submit)
        response = qtw.QTextEdit(readOnly=True)
        for w in (self.url, self.table, self.fname, submit, response):
            widget.layout().addWidget(w)
```

这是一个建立在`QWidget`对象上的简单表单。有一个用于 URL 的输入行，一个用于输入键值对的表格小部件，以及一个用于触发文件对话框并存储所选文件名的按钮。

之后，我们有一个用于发送请求的`submit`按钮和一个只读文本编辑框，用于显示返回的结果。

`fname`按钮在单击时调用`on_file_btn()`，其代码如下：

```py
    def on_file_btn(self):
        filename, accepted = qtw.QFileDialog.getOpenFileName()
        if accepted:
            self.fname.setText(filename)
```

该方法只是调用`QFileDialog`函数来检索要打开的文件名。为了保持简单，我们采取了略微不正统的方法，将文件名存储为我们的`QPushButton`文本。

最后的`MainWindow`方法是`submit()`，当单击`submit`按钮时将调用该方法。在编写我们的 Web 后端之后，我们将回到该方法，因为它的操作取决于我们如何定义该后端。

# POST 后端

我们的 Web 发布后端将基于`QObject`，这样我们就可以使用信号和槽。

首先通过子类化`QObject`并创建一个信号：

```py
class Poster(qtc.QObject):

    replyReceived = qtc.pyqtSignal(str)
```

当我们从服务器接收到我们正在发布的回复时，`replyReceived`信号将被发出，并携带回复的主体作为字符串。

现在让我们创建构造函数：

```py
    def __init__(self):
        super().__init__()
        self.nam = qtn.QNetworkAccessManager()
        self.nam.finished.connect(self.on_reply)
```

在这里，我们正在创建我们的`QNetworkAccessManager`对象，并将其`finished`信号连接到名为`on_reply()`的本地方法。

`on_reply()`方法将如下所示：

```py
    def on_reply(self, reply):
        reply_bytes = reply.readAll()
        reply_string = bytes(reply_bytes).decode('utf-8')
        self.replyReceived.emit(reply_string)
```

回想一下，`finished`信号携带一个`QNetworkReply`对象。我们可以调用它的`readAll()`方法来获取回复的主体作为`QByteArray`。就像我们对原始套接字数据所做的那样，我们首先将其转换为`bytes`对象，然后使用`decode()`方法将其转换为 UTF-8 Unicode 数据。最后，我们将使用来自服务器的字符串发出我们的`replyReceived`信号。

现在我们需要一个方法，实际上会将我们的键值数据和文件发布到 URL。我们将其称为`make_request()`，并从以下位置开始：

```py
    def make_request(self, url, data, filename):
        self.request = qtn.QNetworkRequest(url)
```

与`GET`请求一样，我们首先从提供的 URL 创建一个`QNetworkRequest`对象。但与`GET`请求不同，我们的`POST`请求携带数据负载。为了携带这个负载，我们需要创建一个特殊的对象，可以与请求一起发送。

HTTP 请求可以以几种方式格式化数据负载，但通过 HTTP 传输文件的最常见方式是使用**多部分表单**请求。这种请求包含键值数据和字节编码的文件数据，是通过提交包含输入小部件和文件小部件混合的 HTML 表单获得的。

要在 PyQt 中执行这种请求，我们将首先创建一个`QtNetwork.QHttpMultiPart`对象，如下所示：

```py
        self.multipart = qtn.QHttpMultiPart(
            qtn.QHttpMultiPart.FormDataType)
```

有不同类型的多部分 HTTP 消息，我们通过将`QtNetwork.QHttpMultiPart.ContentType`枚举常量传递给构造函数来定义我们想要的类型。我们在这里使用的是用于一起传输文件和表单数据的`FormDataType`类型。

HTTP 多部分对象是一个包含`QHttpPart`对象的容器，每个对象代表我们数据负载的一个组件。我们需要从传入此方法的数据创建这些部分，并将它们添加到我们的多部分对象中。

让我们从我们的键值对开始：

```py
        for key, value in (data or {}).items():
            http_part = qtn.QHttpPart()
            http_part.setHeader(
                qtn.QNetworkRequest.ContentDispositionHeader,
                f'form-data; name="{key}"'
            )
            http_part.setBody(value.encode('utf-8'))
            self.multipart.append(http_part)
```

每个 HTTP 部分都有一个标头和一个主体。标头包含有关部分的元数据，包括其**Content-Disposition**—也就是它包含的内容。对于表单数据，那将是`form-data`。

因此，对于`data`字典中的每个键值对，我们正在创建一个单独的`QHttpPart`对象，将 Content-Disposition 标头设置为`form-data`，并将`name`参数设置为键。最后，我们将 HTTP 部分的主体设置为我们的值（编码为字节字符串），并将 HTTP 部分添加到我们的多部分对象中。

要包含我们的文件，我们需要做类似的事情：

```py
        if filename:
            file_part = qtn.QHttpPart()
            file_part.setHeader(
                qtn.QNetworkRequest.ContentDispositionHeader,
                f'form-data; name="attachment"; filename="{filename}"'
            )
            filedata = open(filename, 'rb').read()
            file_part.setBody(filedata)
            self.multipart.append(file_part)
```

这一次，我们的 Content-Disposition 标头仍然设置为`form-data`，但也包括一个`filename`参数，设置为我们文件的名称。HTTP 部分的主体设置为文件的内容。请注意，我们以`rb`模式打开文件，这意味着它的二进制内容将被读取为`bytes`对象，而不是将其解释为纯文本。这很重要，因为`setBody()`期望的是 bytes 而不是 Unicode。

现在我们的多部分对象已经构建好了，我们可以调用`QNetworkAccessManager`对象的`post()`方法来发送带有多部分数据的请求：

```py
        self.nam.post(self.request, self.multipart)
```

回到`MainWindow.__init__()`，让我们创建一个`Poster`对象来使用：

```py
        self.poster = Poster()
        self.poster.replyReceived.connect(self.response.setText)
```

由于`replyReceived`将回复主体作为字符串发出，我们可以直接将其连接到响应小部件的`setText`上，以查看服务器的响应。

最后，是时候创建我们的`submit()`回调了：

```py
    def submit(self):
        url = qtc.QUrl(self.url.text())
        filename = self.fname.text()
        if filename == '(No File)':
            filename = None
        data = {}
        for rownum in range(self.table.rowCount()):
            key_item = self.table.item(rownum, 0)
            key = key_item.text() if key_item else None
            if key:
                data[key] = self.table.item(rownum, 1).text()
        self.poster.make_request(url, data, filename)
```

请记住，`make_request()`需要`QUrl`、键值对的`dict`和文件名字符串；因此，这个方法只是遍历每个小部件，提取和格式化数据，然后将其传递给`make_request()`。

# 测试实用程序

如果您可以访问接受 POST 请求和文件上传的服务器，您可以使用它来测试您的脚本；如果没有，您也可以使用本章示例代码中包含的`sample_http_server.py`脚本。这个脚本只需要 Python 3 和标准库，它会将您的 POST 请求回显给您。

在控制台窗口中启动服务器脚本，然后在第二个控制台中运行您的`poster.py`脚本，并执行以下操作：

+   输入 URL 为`http://localhost:8000`

+   向表中添加一些任意的键值对

+   选择要上传的文件（可能是一个不太大的文本文件，比如您的 Python 脚本之一）

+   点击提交帖子

您应该在服务器控制台窗口和 GUI 上的响应文本编辑中看到您请求的打印输出。它应该是这样的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/fbc5b22b-9a2f-4e97-8897-c328187ecffd.png)

总之，使用`QNetworkAccessManager`处理`POST`请求涉及以下步骤：

+   创建`QNetworkAccessManager`并将其`finished`信号连接到将处理`QNetworkReply`的方法

+   创建指向目标 URL 的`QNetworkRequest`

+   创建数据有效负载对象，比如`QHttpMultiPart`对象

+   将请求和数据有效负载传递给`QNetworkAccessManager`对象的`post()`方法

# 总结

在本章中，我们探讨了如何将我们的 PyQt 应用程序连接到网络。您学会了如何使用套接字进行低级编程，包括 UDP 广播应用程序和 TCP 客户端-服务器应用程序。您还学会了如何使用`QNetworkAccessManager`与 HTTP 服务进行交互，从简单的下载到复杂的多部分表单和文件数据上传。

下一章将探讨使用 SQL 数据库存储和检索数据。您将学习如何构建和查询 SQL 数据库，如何使用`QtSQL`模块将 SQL 命令集成到您的应用程序中，以及如何使用 SQL 模型视图组件快速构建数据驱动的 GUI 应用程序。

# 问题

尝试这些问题来测试您从本章中学到的知识：

1.  您正在设计一个应用程序，该应用程序将向本地网络发出状态消息，您将使用管理员工具进行监视。哪种类型的套接字对象是一个不错的选择？

1.  你的 GUI 类有一个名为`self.socket`的`QTcpSocket`对象。你已经将它的`readyRead`信号连接到以下方法，但它不起作用。发生了什么，你该如何修复它？

```py
       def on_ready_read(self):
           while self.socket.hasPendingDatagrams():
               self.process_data(self.socket.readDatagram())
```

1.  使用`QTcpServer`来实现一个简单的服务，监听端口`8080`，并打印接收到的任何请求。让它用你选择的字节字符串回复客户端。

1.  你正在为你的应用程序创建一个下载函数，用于获取一个大数据文件以导入到你的应用程序中。代码不起作用。阅读代码并决定你做错了什么：

```py
       def download(self, url):
        self.manager = qtn.QNetworkAccessManager(
            finished=self.on_finished)
        self.request = qtn.QNetworkRequest(qtc.QUrl(url))
        reply = self.manager.get(self.request)
        with open('datafile.dat', 'wb') as fh:
            fh.write(reply.readAll())
```

1.  修改你的`poster.py`脚本，以便将键值数据发送为 JSON，而不是 HTTP 表单数据。

# 进一步阅读

欲了解更多信息，请参考以下内容：

+   有关数据报包结构的更多信息，请参阅[`en.wikipedia.org/wiki/Datagram`](https://en.wikipedia.org/wiki/Datagram)。

+   随着对网络通信中安全和隐私的关注不断增加，了解如何使用 SSL 是很重要的。请参阅[`doc.qt.io/qt-5/ssl.html`](https://doc.qt.io/qt-5/ssl.html) 了解使用 SSL 的`QtNetwork`工具的概述。

+   **Mozilla 开发者网络**在[`developer.mozilla.org/en-US/docs/Web/HTTP`](https://developer.mozilla.org/en-US/docs/Web/HTTP)上有大量资源，用于理解 HTTP 及其各种标准和协议。


# 第九章：使用 Qt SQL 探索 SQL

大约 40 年来，使用**结构化查询语言**（通常称为 SQL）管理的**关系数据库**一直是存储、检索和分析世界数据的事实标准技术。无论您是创建业务应用程序、游戏、Web 应用程序还是其他应用，如果您的应用处理大量数据，您几乎肯定会使用 SQL。虽然 Python 有许多可用于连接到 SQL 数据库的模块，但 Qt 的`QtSql`模块为我们提供了强大和方便的类，用于将 SQL 数据集成到 PyQt 应用程序中。

在本章中，您将学习如何构建基于数据库的 PyQt 应用程序，我们将涵盖以下主题：

+   SQL 基础知识

+   使用 Qt 执行 SQL 查询

+   使用模型视图小部件与 SQL

# 技术要求

除了您自第一章以来一直在使用的基本设置，*开始使用 PyQt*，您还需要在 GitHub 存储库中找到的示例代码，网址为[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter09`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter09)。

您可能还会发现拥有**SQLite**的副本对练习 SQL 示例很有帮助。SQLite 是免费的，可以从[`sqlite.org/download.html`](https://sqlite.org/download.html)下载。

查看以下视频，了解代码的实际操作：[`bit.ly/2M5xu1r`](http://bit.ly/2M5xu1r)

# SQL 基础知识

在我们深入了解`QtSql`提供的内容之前，您需要熟悉 SQL 的基础知识。本节将为您快速概述如何在 SQL 数据库中创建、填充、更改和查询数据。如果您已经了解 SQL，您可能希望跳到本章的 PyQt 部分。

SQL 在语法和结构上与 Python 非常不同。它是一种**声明式**语言，意味着我们描述我们想要的结果，而不是用于获得结果的过程。与 SQL 数据库交互时，我们执行**语句**。每个语句由一个 SQL**命令**和一系列**子句**组成，每个子句进一步描述所需的结果。语句以分号结束。

尽管 SQL 是标准化的，但所有 SQL 数据库实现都提供其自己的对标准语言的修改和扩展。我们将学习 SQL 的 SQLite 方言，它与标准 SQL 相当接近。

与 Python 不同，SQL 通常是不区分大小写的语言；但是，长期以来，将 SQL 关键字写成大写字母是一种惯例。这有助于它们与数据和对象名称区分开。我们将在本书中遵循这个惯例，但对于您的代码来说是可选的。

# 创建表

SQL 数据库由关系组成，也称为**表**。表是由行和列组成的二维数据结构。表中的每一行代表我们拥有信息的单个项目，每一列代表我们正在存储的信息类型。

使用`CREATE TABLE`命令定义表，如下所示：

```py
CREATE TABLE coffees (
        id  INTEGER PRIMARY KEY,
        coffee_brand TEXT NOT NULL,
        coffee_name TEXT NOT NULL,
        UNIQUE(coffee_brand, coffee_name)
        );
```

`CREATE TABLE`语句后面跟着表名和列定义列表。在这个例子中，`coffees`是我们正在创建的表的名称，列定义在括号内。每一列都有一个名称，一个数据类型，以及描述有效值的任意数量的**约束**。

在这种情况下，我们有三列：

+   `id`是一个整数列。它被标记为**主键**，这意味着它将是一个可以用来标识行的唯一值。

+   `coffee_brand`和`coffee_name`都是文本列，具有`NOT NULL`约束，这意味着它们不能有`NULL`值。

约束也可以在多个列上定义。在字段后添加的`UNIQUE`约束不是字段，而是一个表级约束，确保每行的`coffee _brand`和`coffee _name`的组合对于每行都是唯一的。

`NULL`是 SQL 中 Python 的`None`的等价物。它表示信息的缺失。

SQL 数据库至少支持文本、数字、日期、时间和二进制对象数据类型；但不少数据库实现会通过扩展 SQL 来支持额外的数据类型，比如货币或 IP 地址类型。许多数据库还有数字类型的`SMALL`和`BIG`变体，允许开发人员微调列使用的存储空间。

尽管简单的二维表很有用，但 SQL 数据库的真正威力在于将多个相关表连接在一起，例如：

```py
CREATE TABLE roasts (
        id INTEGER PRIMARY KEY,
        description TEXT NOT NULL UNIQUE,
        color TEXT NOT NULL UNIQUE
        );

CREATE TABLE coffees (
        id  INTEGER PRIMARY KEY,
        coffee_brand TEXT NOT NULL,
        coffee_name TEXT NOT NULL,
        roast_id INTEGER REFERENCES roasts(id),
        UNIQUE(coffee_brand, coffee_name)
        );

CREATE TABLE reviews (
        id INTEGER PRIMARY KEY,
        coffee_id REFERENCES coffees(id),
        reviewer TEXT NOT NULL,
        review_date DATE NOT NULL DEFAULT CURRENT_DATE,
        review TEXT NOT NULL
        );
```

`coffees`中的`roast_id`列保存与`roasts`的主键匹配的值，如`REFERENCES`约束所示。每个`coffees`记录不需要在每条咖啡记录中重写烘焙的描述和颜色，而是简单地指向`roasts`中保存有关该咖啡烘焙信息的行。同样，`reviews`表包含`coffee_id`列，它指向一个单独的`coffees`条目。这些关系称为**外键关系**，因为该字段引用另一个表的键。

在多个相关表中对数据进行建模可以减少重复，并强制执行数据一致性。想象一下，如果所有三个表中的数据合并成一张咖啡评论表，那么同一款咖啡产品的两条评论可能会指定不同的烘焙程度。这是不可能的，而且在关系型数据表中也不会发生。

# 插入和更新数据

创建表后，我们可以使用`INSERT`语句添加新的数据行，语法如下：

```py
INSERT INTO table_name(column1, column2, ...)
    VALUES (value1, value2, ...), (value3, value4, ...);
```

例如，让我们向`roasts`中插入一些行：

```py
INSERT INTO roasts(description, color) VALUES
    ('Light', '#FFD99B'),
    ('Medium', '#947E5A'),
    ('Dark', '#473C2B'),
    ('Burnt to a Crisp', '#000000');
```

在这个例子中，我们为`roasts`表中的每条新记录提供了`description`和`color`值。`VALUES`子句包含一个元组列表，每个元组代表一行数据。这些元组中的值的数量和数据类型*必须*与指定的列的数量和数据类型匹配。

请注意，我们没有包括所有的列——`id`缺失。我们在`INSERT`语句中不指定的任何字段都将获得默认值，除非我们另有规定，否则默认值为`NULL`。

在 SQLite 中，`INTEGER PRIMARY KEY`字段具有特殊行为，其默认值在每次插入时自动递增。因此，此查询产生的`id`值将为`1`（`Light`），`2`（`Medium`），`3`（`Dark`）和`4`（`Burnt to a Crisp`）。

这一点很重要，因为我们需要该键值来插入记录到我们的`coffees`表中：

```py
INSERT INTO coffees(coffee_brand, coffee_name, roast_id) VALUES
    ('Dumpy''s Donuts', 'Breakfast Blend', 2),
    ('Boise''s Better than Average', 'Italian Roast', 3),
    ('Strawbunks', 'Sumatra', 2),
    ('Chartreuse Hillock', 'Pumpkin Spice', 1),
    ('Strawbunks', 'Espresso', 3),
    ('9 o''clock', 'Original Decaf', 2);
```

与 Python 不同，SQL 字符串文字*必须*只使用单引号。双引号字符串被解释为数据库对象的名称，比如表或列。要在字符串中转义单引号，请使用两个单引号，就像我们在前面的查询中所做的那样。

由于我们的外键约束，不可能在`coffees`中插入包含不存在于`roasts`中的`roast_id`的行。例如，这将返回一个错误：

```py
INSERT INTO coffees(coffee_brand, coffee_name, roast_id) VALUES
    ('Minwell House', 'Instant', 48);
```

请注意，我们可以在`roast_id`字段中插入`NULL`；除非该列被定义为`NOT NULL`约束，否则`NULL`是唯一不需要遵守外键约束的值。

# 更新现有行

要更新表中的现有行，您可以使用`UPDATE`语句，如下所示：

```py
UPDATE coffees SET roast_id = 4 WHERE id = 2;
```

`SET`子句后面是要更改的字段的值分配列表，`WHERE`子句描述了必须为真的条件，如果要更新特定行。在这种情况下，我们将把`id`列为`2`的记录的`roast_id`列的值更改为`4`。

SQL 使用单个等号来进行赋值和相等操作。它永远不会使用 Python 使用的双等号。

更新操作也可以影响多条记录，就像这样：

```py
UPDATE coffees SET roast_id = roast_id + 1
    WHERE coffee_brand LIKE 'Strawbunks';
```

在这种情况下，我们通过将`Strawbunks`咖啡的所有`roast_id`值增加 1 来增加。每当我们在查询中引用列的值时，该值将是同一行中的列的值。

# 选择数据

SQL 中最重要的操作可能是`SELECT`语句，用于检索数据。一个简单的`SELECT`语句看起来像这样：

```py
SELECT reviewer, review_date
FROM reviews
WHERE  review_date > '2019-03-01'
ORDER BY reviewer DESC;
```

`SELECT`命令后面跟着一个字段列表，或者跟着`*`符号，表示*所有字段*。`FROM`子句定义了数据的来源；在这种情况下，是`reviews`表。`WHERE`子句再次定义了必须为真的条件才能包括行。在这种情况下，我们只包括比 2019 年 3 月 1 日更新的评论，通过比较每行的`review_date`字段（它是一个`DATE`类型）和字符串`'2019-03-01'`（SQLite 将其转换为`DATE`以进行比较）。最后，`ORDER BY`子句确定了结果集的排序方式。

# 表连接

`SELECT`语句总是返回一个值表。即使你的结果集只有一个值，它也会在一个行和一列的表中，而且没有办法从一个查询中返回多个表。然而，我们可以通过将数据合并成一个表来从多个表中提取数据。

这可以在`FROM`子句中使用`JOIN`来实现，例如：

```py
SELECT coffees.coffee_brand,
    coffees.coffee_name,
    roasts.description AS roast,
    COUNT(reviews.id) AS reviews
FROM coffees
    JOIN roasts ON coffees.roast_id = roasts.id
    LEFT OUTER JOIN reviews ON reviews.coffee_id = coffees.id
GROUP BY coffee_brand, coffee_name, roast
ORDER BY reviews DESC;
```

在这种情况下，我们的`FROM`子句包含两个`JOIN`语句。第一个将`coffees`与`roasts`通过匹配`coffees`中的`roast_id`字段和`roasts`中的`id`字段进行连接。第二个通过匹配`reviews`表中的`coffee_id`列和`coffees`表中的`id`列进行连接。

连接略有不同：请注意`reviews`连接是一个`LEFT OUTER JOIN`。这意味着我们包括了`coffees`中没有任何匹配`reviews`记录的行；默认的`JOIN`是一个`INNER`连接，意味着只有在两个表中都有匹配记录的行才会显示。

在这个查询中，我们还使用了一个**聚合函数**，`COUNT()`。`COUNT()`函数只是计算匹配的行数。聚合函数要求我们指定一个`GROUP BY`子句，列出将作为聚合基础的字段。换句话说，对于每个`coffee_brand`、`coffee_name`和`roast`的唯一组合，我们将得到数据库中评论记录的总数。其他标准的聚合函数包括`SUM`（用于对所有匹配值求和）、`MIN`（返回所有匹配值的最小值）和`MAX`（返回所有匹配值的最大值）。不同的数据库实现还包括它们自己的自定义聚合函数。

# SQL 子查询

`SELECT`语句可以通过将其放在括号中嵌入到另一个 SQL 语句中。这被称为**子查询**。它可以嵌入的确切位置取决于查询预期返回的数据类型：

+   如果语句将返回一个单行单列，它可以嵌入到期望单个值的任何地方

+   如果语句将返回一个单列多行，它可以嵌入到期望值列表的任何地方

+   如果语句将返回多行多列，它可以嵌入到期望值表的任何地方

考虑这个查询：

```py
SELECT coffees.coffee_brand, coffees.coffee_name
FROM coffees
    JOIN (
    SELECT * FROM roasts WHERE id > (
        SELECT id FROM roasts WHERE description = 'Medium'
            )) AS dark_roasts
    ON coffees.roast_id = dark_roasts.id
WHERE coffees.id IN (
    SELECT coffee_id FROM reviews WHERE reviewer = 'Maxwell');
```

这里有三个子查询。第一个位于`FROM`子句中：

```py
    (SELECT * FROM roasts WHERE id > (
        SELECT id FROM roasts WHERE description = 'Medium'
            )) AS dark_roasts
```

因为它以`SELECT *`开头，我们可以确定它将返回一个数据表（或者没有数据，但这不重要）。因此，它可以在`FROM`子句中使用，因为这里期望一个表。请注意，我们需要使用`AS`关键字给子查询一个名称。在`FROM`子句中使用子查询时，这是必需的。

这个子查询包含了它自己的子查询：

```py
        SELECT id FROM roasts WHERE description = 'Medium'
```

这个查询很可能会给我们一个单一的值，所以我们在期望得到单一值的地方使用它；在这种情况下，作为大于表达式的操作数。如果由于某种原因，这个查询返回了多行，我们的查询将会返回一个错误。

我们最终的子查询在`WHERE`子句中：

```py
    SELECT coffee_id FROM reviews WHERE reviewer = 'Maxwell'
```

这个表达式保证只返回一列，但可能返回多行。因此，我们将其用作`IN`关键字的参数，该关键字期望一个值列表。

子查询很强大，但如果我们对数据的假设不正确，有时也会导致减速和错误。

# 学习更多

我们在这里只是简单地介绍了 SQL 的基础知识，但这应该足够让您开始创建和使用简单的数据库，并涵盖了本章中将要使用的 SQL。在本章末尾的*进一步阅读*部分中，您将看到如何将 SQL 知识与 PyQt 结合起来创建数据驱动的应用程序。

# 使用 Qt 执行 SQL 查询

使用不同的 SQL 实现可能会令人沮丧：不仅 SQL 语法有细微差异，而且用于连接它们的 Python 库在它们实现的各种方法上经常不一致。虽然在某些方面，它不如更知名的 Python SQL 库方便，但`QtSQL`确实为我们提供了一种一致的抽象 API，以一致的方式处理各种数据库产品。正确利用时，它还可以为我们节省大量代码。

为了学习如何在 PyQt 中处理 SQL 数据，我们将为本章*SQL 基础*中创建的咖啡数据库构建一个图形前端。

可以使用以下命令从示例代码创建完整版本的数据库：

`$ sqlite3 coffee.db -init coffee.sql`。在前端工作之前，您需要创建这个数据库文件。

# 构建一个表单

我们的咖啡数据库有三个表：咖啡产品列表、烘焙列表和产品评论表。我们的 GUI 将设计如下：

+   它将有一个咖啡品牌和产品列表

+   当我们双击列表中的项目时，它将打开一个表单，显示关于咖啡的所有信息，以及与该产品相关的所有评论

+   它将允许我们添加新产品和新评论，或编辑任何现有信息

让我们首先从第四章中复制您的基本 PyQt 应用程序模板，*使用 QMainWindow 构建应用程序*，保存为`coffee_list1.py`。然后，像这样添加一个`QtSQL`的导入：

```py
from PyQt5 import QtSql as qts
```

现在我们要创建一个表单，显示关于我们的咖啡产品的信息。基本表单如下：

```py
class CoffeeForm(qtw.QWidget):

    def __init__(self, roasts):
        super().__init__()
        self.setLayout(qtw.QFormLayout())
        self.coffee_brand = qtw.QLineEdit()
        self.layout().addRow('Brand: ', self.coffee_brand)
        self.coffee_name = qtw.QLineEdit()
        self.layout().addRow('Name: ', self.coffee_name)
        self.roast = qtw.QComboBox()
        self.roast.addItems(roasts)
        self.layout().addRow('Roast: ', self.roast)
        self.reviews = qtw.QTableWidget(columnCount=3)
        self.reviews.horizontalHeader().setSectionResizeMode(
            2, qtw.QHeaderView.Stretch)
        self.layout().addRow(self.reviews)
```

这个表单有品牌、名称和咖啡烘焙的字段，以及一个用于显示评论的表格小部件。请注意，构造函数需要`roasts`，这是一个咖啡烘焙的列表，用于组合框；我们希望从数据库中获取这些，而不是将它们硬编码到表单中，因为新的烘焙可能会被添加到数据库中。

这个表单还需要一种方法来显示咖啡产品。让我们创建一个方法，它将获取咖啡数据并对其进行审查，并用它填充表单：

```py
    def show_coffee(self, coffee_data, reviews):
        self.coffee_brand.setText(coffee_data.get('coffee_brand'))
        self.coffee_name.setText(coffee_data.get('coffee_name'))
        self.roast.setCurrentIndex(coffee_data.get('roast_id'))
        self.reviews.clear()
        self.reviews.setHorizontalHeaderLabels(
            ['Reviewer', 'Date', 'Review'])
        self.reviews.setRowCount(len(reviews))
        for i, review in enumerate(reviews):
            for j, value in enumerate(review):
                self.reviews.setItem(i, j, qtw.QTableWidgetItem(value))
```

这个方法假设`coffee_data`是一个包含品牌、名称和烘焙 ID 的`dict`对象，而`reviews`是一个包含评论数据的元组列表。它只是遍历这些数据结构，并用数据填充每个字段。

在`MainWindow.__init__()`中，让我们开始主 GUI：

```py
        self.stack = qtw.QStackedWidget()
        self.setCentralWidget(self.stack)
```

我们将使用`QStackedWidget`在我们的咖啡列表和咖啡表单小部件之间进行切换。请记住，这个小部件类似于`QTabWidget`，但没有选项卡。

在我们可以构建更多 GUI 之前，我们需要从数据库中获取一些信息。让我们讨论如何使用`QtSQL`连接到数据库。

# 连接和进行简单查询

要使用`QtSQL`与 SQL 数据库，我们首先必须建立连接。这有三个步骤：

+   创建连接对象

+   配置连接对象

+   打开连接

在`MainWindow.__init__()`中，让我们创建我们的数据库连接：

```py
        self.db = qts.QSqlDatabase.addDatabase('QSQLITE')
```

我们不是直接创建`QSqlDatabase`对象，而是通过调用静态的`addDatabase`方法创建一个，其中包含我们将要使用的数据库驱动程序的名称。在这种情况下，我们使用的是 Qt 的 SQLite3 驱动程序。Qt 5.12 内置了九个驱动程序，包括 MySQL（`QMYSQL`）、PostgreSQL（`QPSQL`）和 ODBC 连接（包括 Microsoft SQL Server）（`QODBC`）。完整的列表可以在[`doc.qt.io/qt-5/qsqldatabase.html#QSqlDatabase-2`](https://doc.qt.io/qt-5/qsqldatabase.html#QSqlDatabase-2)找到。

一旦我们的数据库对象创建好了，我们需要用任何必需的连接设置来配置它，比如主机、用户、密码和数据库名称。对于 SQLite，我们只需要指定一个文件名，如下所示：

```py
        self.db.setDatabaseName('coffee.db')
```

我们可以配置的一些属性包括以下内容：

+   `hostName`—数据库服务器的主机名或 IP

+   `port`—数据库服务侦听的网络端口

+   `userName`—连接的用户名

+   `password`—用于身份验证的密码

+   `connectOptions`—附加连接选项的字符串

所有这些都可以使用通常的访问器方法进行配置或查询（例如`hostName()`和`setHostName()`）。如果你使用的是 SQLite 之外的其他东西，请查阅其文档，看看你需要配置哪些设置。

连接对象配置好之后，我们可以使用`open()`方法打开连接。这个方法返回一个布尔值，表示连接是否成功。如果失败，我们可以通过检查连接对象的`lastError`属性来找出失败的原因。

这段代码演示了我们可能会这样做：

```py
        if not self.db.open():
            error = self.db.lastError().text()
            qtw.QMessageBox.critical(
                None, 'DB Connection Error',
                'Could not open database file: '
                f'{error}')
            sys.exit(1)
```

在这里，我们调用`self.db.open()`，如果失败，我们从`lastError`中检索错误并在对话框中显示它。`lastError()`调用返回一个`QSqlError`对象，其中包含有关错误的数据和元数据；要提取实际的错误文本，我们调用它的`text()`方法。

# 获取有关数据库的信息

一旦我们的连接实际连接上了，我们就可以使用它来开始检查数据库。例如，`tables()`方法列出数据库中的所有表。我们可以使用这个方法来检查所有必需的表是否存在，例如：

```py
        required_tables = {'roasts', 'coffees', 'reviews'}
        tables = self.db.tables()
        missing_tables = required_tables - set(tables)
        if missing_tables:
            qtw.QMessageBox.critica(
                None, 'DB Integrity Error'
                'Missing tables, please repair DB: '
                f'{missing_tables}')
            sys.exit(1)
```

在这里，我们比较数据库中存在的表和必需表的集合。如果我们发现任何缺失，我们将显示错误并退出。

`set`对象类似于列表，不同之处在于其中的所有项目都是唯一的，并且它们允许进行一些有用的比较。在这种情况下，我们正在减去集合以找出`required_tables`中是否有任何不在`tables`中的项目。

# 进行简单的查询

与我们的 SQL 数据库交互依赖于`QSqlQuery`类。这个类表示对 SQL 引擎的请求，可以用来准备、执行和检索有关查询的数据和元数据。

我们可以使用数据库对象的`exec()`方法向数据库发出 SQL 查询：

```py
        query = self.db.exec('SELECT count(*) FROM coffees')
```

`exec()`方法从我们的字符串创建一个`QSqlQuery`对象，执行它，并将其返回给我们。然后我们可以从`query`对象中检索我们查询的结果：

```py
        query.next()
        count = query.value(0)
        print(f'There are {count} coffees in the database.')
```

重要的是要对这里发生的事情有一个心理模型，因为这并不是非常直观的。正如你所知，SQL 查询总是返回一张数据表，即使只有一行和一列。`QSqlQuery`有一个隐式的*游标*，它将指向数据的一行。最初，这个游标指向无处，但调用`next()`方法将它移动到下一个可用的数据行，这种情况下是第一行。然后使用`value()`方法来检索当前选定行中给定列的值（`value(0)`将检索第一列，`value(1)`将检索第二列，依此类推）。

所以，这里发生的情况类似于这样：

+   查询被执行并填充了数据。游标指向无处。

+   我们调用`next()`将光标指向第一行。

+   我们调用`value(0)`来检索行的第一列的值。

要从`QSqlQuery`对象中检索数据列表或表，我们只需要重复最后两个步骤，直到`next()`返回`False`（表示没有下一行要指向）。例如，我们需要一个咖啡烘焙的列表来填充我们的表单，所以让我们检索一下：

```py
        query = self.db.exec('SELECT * FROM roasts ORDER BY id')
        roasts = []
        while query.next():
            roasts.append(query.value(1))
```

在这种情况下，我们要求查询从`roasts`表中获取所有数据，并按`id`排序。然后，我们在查询对象上调用`next()`，直到它返回`False`；每次，提取第二个字段的值（`query.value(1)`）并将其附加到我们的`roasts`列表中。

现在我们有了这些数据，我们可以创建我们的`CoffeeForm`并将其添加到应用程序中：

```py
        self.coffee_form = CoffeeForm(roasts)
        self.stack.addWidget(self.coffee_form)
```

除了使用`value()`检索值之外，我们还可以通过调用`record()`方法来检索整行。这将返回一个包含当前行数据的`QSqlRecord`对象（如果没有指向任何行，则返回一个空记录）。我们将在本章后面使用`QSqlRecord`。

# 准备好的查询

很多时候，数据需要从应用程序传递到 SQL 查询中。例如，我们需要编写一个方法，通过 ID 号查找单个咖啡，以便我们可以在我们的表单中显示它。

我们可以开始编写该方法，就像这样：

```py
    def show_coffee(self, coffee_id):
        query = self.db.exec(f'SELECT * FROM coffees WHERE id={coffee_id}')
```

在这种情况下，我们使用格式化字符串直接将`coffee_id`的值放入我们的查询中。不要这样做！

使用字符串格式化或连接构建 SQL 查询可能会导致所谓的**SQL 注入漏洞**，其中传递一个特制的值可能会暴露或破坏数据库中的数据。在这种情况下，我们假设`coffee_id`将是一个整数，但假设一个恶意用户能够向这个函数发送这样的字符串：

```py
0; DELETE FROM coffees;
```

我们的字符串格式化将评估这一点，并生成以下 SQL 语句：

```py
SELECT * FROM coffees WHERE id=0; DELETE FROM coffees;
```

结果将是我们的`coffees`表中的所有行都将被删除！虽然在这种情况下可能看起来微不足道或荒谬，但 SQL 注入漏洞是许多数据泄露和黑客丑闻背后的原因，这些你在新闻中读到的。在处理重要数据时（还有比咖啡更重要的东西吗？），保持防御是很重要的。

执行此查询并保护数据库免受此类漏洞的正确方法是使用准备好的查询。**准备好的查询**是一个包含我们可以绑定值的变量的查询。数据库驱动程序将适当地转义我们的值，以便它们不会被意外地解释为 SQL 代码。

这个版本的代码使用了一个准备好的查询：

```py
        query1 = qts.QSqlQuery(self.db)
        query1.prepare('SELECT * FROM coffees WHERE id=:id')
        query1.bindValue(':id', coffee_id)
        query1.exec()
```

在这里，我们明确地创建了一个连接到我们的数据库的空`QSqlQuery`对象。然后，我们将 SQL 字符串传递给`prepare()`方法。请注意我们查询中使用的`:id`字符串；冒号表示这是一个变量。一旦我们有了准备好的查询，我们就可以开始将查询中的变量绑定到我们代码中的变量，使用`bindValue()`。在这种情况下，我们将`：id` SQL 变量绑定到我们的`coffee_id` Python 变量。

一旦我们的查询准备好并且变量被绑定，我们调用它的`exec()`方法来执行它。

一旦执行，我们可以从查询对象中提取数据，就像以前做过的那样：

```py
        query1.next()
        coffee = {
            'id': query1.value(0),
            'coffee_brand': query1.value(1),
            'coffee_name': query1.value(2),
            'roast_id': query1.value(3)
        }
```

让我们尝试相同的方法来检索咖啡的评论数据：

```py
        query2 = qts.QSqlQuery()
        query2.prepare('SELECT * FROM reviews WHERE coffee_id=:id')
        query2.bindValue(':id', coffee_id)
        query2.exec()
        reviews = []
        while query2.next():
            reviews.append((
                query2.value('reviewer'),
                query2.value('review_date'),
                query2.value('review')
            ))
```

请注意，这次我们没有将数据库连接对象传递给`QSqlQuery`构造函数。由于我们只有一个连接，所以不需要将数据库连接对象传递给`QSqlQuery`；`QtSQL`将自动在任何需要数据库连接的方法调用中使用我们的默认连接。

还要注意，我们使用列名而不是它们的编号从我们的`reviews`表中获取值。这同样有效，并且是一个更友好的方法，特别是在有许多列的表中。

我们将通过填充和显示我们的咖啡表单来完成这个方法：

```py
        self.coffee_form.show_coffee(coffee, reviews)
        self.stack.setCurrentWidget(self.coffee_form)
```

请注意，准备好的查询只能将*值*引入查询中。例如，您不能准备这样的查询：

```py
      query.prepare('SELECT * from :table ORDER BY :column')
```

如果您想构建包含可变表或列名称的查询，不幸的是，您将不得不使用字符串格式化。在这种情况下，请注意可能出现 SQL 注入的潜在风险，并采取额外的预防措施，以确保被插入的值是您认为的值。

# 使用 QSqlQueryModel

手动将数据填充到表小部件中似乎是一项繁琐的工作；如果您回忆起第五章，*使用模型视图类创建数据接口*，Qt 为我们提供了可以为我们完成繁琐工作的模型视图类。我们可以对`QAbstractTableModel`进行子类化，并创建一个从 SQL 查询中填充的模型，但幸运的是，`QtSql`已经以`QSqlQueryModel`的形式提供了这个功能。

正如其名称所示，`QSqlQueryModel`是一个使用 SQL 查询作为数据源的表模型。我们将使用它来创建我们的咖啡产品列表，就像这样：

```py
        coffees = qts.QSqlQueryModel()
        coffees.setQuery(
            "SELECT id, coffee_brand, coffee_name AS coffee "
            "FROM coffees ORDER BY id")
```

创建模型后，我们将其`query`属性设置为 SQL `SELECT`语句。模型的数据将从此查询返回的表中获取。

与`QSqlQuery`一样，我们不需要显式传递数据库连接，因为只有一个。如果您有多个活动的数据库连接，您应该将要使用的连接传递给`QSqlQueryModel()`。

一旦我们有了模型，我们就可以在`QTableView`中使用它，就像这样：

```py
        self.coffee_list = qtw.QTableView()
        self.coffee_list.setModel(coffees)
        self.stack.addWidget(self.coffee_list)
        self.stack.setCurrentWidget(self.coffee_list)
```

就像我们在第五章中所做的那样，*使用模型视图类创建数据接口*，我们创建了`QTableView`并将模型传递给其`setModel()`方法。然后，我们将表视图添加到堆叠小部件中，并将其设置为当前可见的小部件。

默认情况下，表视图将使用查询的列名作为标题标签。我们可以通过使用模型的`setHeaderData()`方法来覆盖这一点，就像这样：

```py
        coffees.setHeaderData(1, qtc.Qt.Horizontal, 'Brand')
        coffees.setHeaderData(2, qtc.Qt.Horizontal, 'Product')
```

请记住，`QSqlQueryModel`对象处于只读模式，因此无法将此表视图设置为可编辑，以便更改关于我们咖啡列表的详细信息。我们将在下一节中看看如何使用可编辑的 SQL 模型，*在没有 SQL 的情况下使用模型视图小部件*。不过，首先让我们完成我们的 GUI。

# 完成 GUI

现在我们的应用程序既有列表又有表单小部件，让我们在它们之间启用一些导航。首先，创建一个工具栏按钮，用于从咖啡表单切换到列表：

```py
        navigation = self.addToolBar("Navigation")
        navigation.addAction(
            "Back to list",
            lambda: self.stack.setCurrentWidget(self.coffee_list))
```

接下来，我们将配置我们的列表，以便双击项目将显示包含该咖啡记录的咖啡表单。请记住，我们的`MainView.show_coffee()`方法需要咖啡的`id`值，但列表小部件的`itemDoubleClicked`信号携带了点击的模型索引。让我们在`MainView`上创建一个方法来将一个转换为另一个：

```py
    def get_id_for_row(self, index):
        index = index.siblingAtColumn(0)
        coffee_id = self.coffee_list.model().data(index)
        return coffee_id
```

由于`id`在模型的列`0`中，我们使用`siblingAtColumn(0)`从被点击的任意行中检索列`0`的索引。然后我们可以通过将该索引传递给`model().data()`来检索`id`值。

现在我们有了这个，让我们为`itemDoubleClicked`信号添加一个连接：

```py
        self.coffee_list.doubleClicked.connect(
            lambda x: self.show_coffee(self.get_id_for_row(x)))
```

在这一点上，我们对我们的咖啡数据库有一个简单的只读应用程序。我们当然可以继续使用当前的 SQL 查询方法来管理我们的数据，但 Qt 提供了一种更优雅的方法。我们将在下一节中探讨这种方法。

# 在没有 SQL 的情况下使用模型视图小部件

在上一节中使用了`QSqlQueryModel`之后，您可能会想知道这种方法是否可以进一步泛化，直接访问表并避免完全编写 SQL 查询。您可能还想知道我们是否可以避开`QSqlQueryModel`的只读限制。对于这两个问题的答案都是*是*，这要归功于`QSqlTableModel`和`QSqlRelationalTableModels`。

要了解这些是如何工作的，让我们回到应用程序的起点重新开始：

1.  从一个新的模板副本开始，将其命名为`coffee_list2.py`。添加`QtSql`的导入和第一个应用程序中的数据库连接代码。现在让我们开始使用表模型构建。对于简单的情况，我们想要从单个数据库表创建模型，我们可以使用`QSqlTableModel`：

```py
self.reviews_model = qts.QSqlTableModel()
self.reviews_model.setTable('reviews')
```

1.  `reviews_model`现在是`reviews`表的可读/写表模型。就像我们在第五章中使用 CSV 表模型编辑 CSV 文件一样，我们可以使用这个模型来查看和编辑`reviews`表。对于需要从连接表中查找值的表，我们可以使用`QSqlRelationalTableModel`：

```py
self.coffees_model = qts.QSqlRelationalTableModel()
self.coffees_model.setTable('coffees')
```

1.  再一次，我们有一个可以用来查看和编辑 SQL 表中数据的表模型；这次是`coffees`表。但是，`coffees`表有一个引用`roasts`表的`roast_id`列。`roast_id`对应于应用程序用户没有意义，他们更愿意使用烘焙的`description`列。为了在我们的模型中用`roasts.description`替换`roast_id`，我们可以使用`setRelation()`函数将这两个表连接在一起，就像这样：

```py
        self.coffees_model.setRelation(
            self.coffees_model.fieldIndex('roast_id'),
            qts.QSqlRelation('roasts', 'id', 'description')
        )
```

这个方法接受两个参数。第一个是我们要连接的主表的列号，我们可以使用模型的`fieldIndex()`方法按名称获取。第二个是`QSqlRelation`对象，它表示外键关系。它所需的参数是表名（`roasts`），连接表中的相关列（`roasts.id`），以及此关系的显示字段（`description`）。

设置这种关系的结果是，我们的表视图将使用与`roasts`中的`description`列相关的值，而不是`roast_id`值，当我们将`coffee_model`连接到视图时。

1.  在我们可以将模型连接到视图之前，我们需要再走一步：

```py
self.mapper.model().select()
```

每当我们配置或重新配置`QSqlTableModel`或`QSqlRelationalTableModel`时，我们必须调用它的`select()`方法。这会导致模型生成并运行 SQL 查询，以刷新其数据并使其可用于视图。

1.  现在我们的模型准备好了，我们可以在视图中尝试一下：

```py
        self.coffee_list = qtw.QTableView()
        self.coffee_list.setModel(self.coffees_model)
```

1.  在这一点上运行程序，您应该会得到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/85eb90e0-609f-4e31-9fff-1299a9c8b9b1.png)

请注意，由于我们的关系表模型，我们有一个包含烘焙描述的`description`列，而不是`roast_id`列。正是我们想要的。

还要注意，在这一点上，您可以查看和编辑咖啡列表中的任何值。`QSqlRelationalTableModel`默认是可读/写的，我们不需要对视图进行任何调整来使其可编辑。但是，它可能需要一些改进。

# 代理和数据映射

虽然我们可以编辑列表，但我们还不能添加或删除列表中的项目；在继续进行咖啡表单之前，让我们添加这个功能。

首先创建一些指向`MainView`方法的工具栏操作：

```py
        toolbar = self.addToolBar('Controls')
        toolbar.addAction('Delete Coffee(s)', self.delete_coffee)
        toolbar.addAction('Add Coffee', self.add_coffee)
```

现在我们将为这些操作编写`MainView`方法：

```py
    def delete_coffee(self):
        selected = self.coffee_list.selectedIndexes()
        for index in selected or []:
            self.coffees_model.removeRow(index.row())

    def add_coffee(self):
        self.stack.setCurrentWidget(self.coffee_list)
        self.coffees_model.insertRows(
            self.coffees_model.rowCount(), 1)
```

要从模型中删除一行，我们可以调用其`removeRow()`方法，传入所需的行号。这可以从`selectedIndexes`属性中获取。要添加一行，我们调用模型的`insertRows()`方法。这段代码应该很熟悉，来自第五章，*使用模型-视图类创建数据接口*。

现在，如果您运行程序并尝试添加一行，注意您基本上会得到一个`QLineEdit`，用于在每个单元格中输入数据。这对于咖啡品牌和产品名称等文本字段来说是可以的，但对于烘焙描述，更合理的是使用一些限制我们使用正确值的东西，比如下拉框。

在 Qt 的模型-视图系统中，决定为数据绘制什么小部件的对象称为**代理**。代理是视图的属性，通过设置我们自己的代理对象，我们可以控制数据的呈现方式以进行查看或编辑。

在由`QSqlRelationalTableModel`支持的视图的情况下，我们可以利用一个名为`QSqlRelationalDelegate`的现成委托，如下所示：

```py
self.coffee_list.setItemDelegate(qts.QSqlRelationalDelegate())
```

`QSqlRelationalDelegate`自动为已设置`QSqlRelation`的任何字段提供组合框。通过这个简单的更改，您应该发现`description`列现在呈现为一个组合框，其中包含来自`roasts`表的可用描述值。好多了！

# 数据映射

现在我们的咖啡列表已经很完善了，是时候处理咖啡表单了，这将允许我们显示和编辑单个产品及其评论的详细信息

让我们从表单的咖啡详情部分的 GUI 代码开始：

```py
class CoffeeForm(qtw.QWidget):

    def __init__(self, coffees_model, reviews_model):
        super().__init__()
        self.setLayout(qtw.QFormLayout())
        self.coffee_brand = qtw.QLineEdit()
        self.layout().addRow('Brand: ', self.coffee_brand)
        self.coffee_name = qtw.QLineEdit()
        self.layout().addRow('Name: ', self.coffee_name)
        self.roast = qtw.QComboBox()
        self.layout().addRow('Roast: ', self.roast)
```

表单的这一部分是我们在咖啡列表中显示的完全相同的信息，只是现在我们使用一系列不同的小部件来显示单个记录。将我们的`coffees`表模型连接到视图是直接的，但是我们如何将模型连接到这样的表单呢？一个答案是使用`QDataWidgetMapper`对象。

`QDataWidgetMapper`的目的是将模型中的字段映射到表单中的小部件。为了了解它是如何工作的，让我们将一个添加到`CoffeeForm`中：

```py
        self.mapper = qtw.QDataWidgetMapper(self)
        self.mapper.setModel(coffees_model)
        self.mapper.setItemDelegate(
            qts.QSqlRelationalDelegate(self))
```

映射器位于模型和表单字段之间，将它们之间的列进行转换。为了确保数据从表单小部件正确写入到模型中的关系字段，我们还需要设置适当类型的`itemDelegate`，在这种情况下是`QSqlRelationalDelegate`。

现在我们有了映射器，我们需要使用`addMapping`方法定义字段映射：

```py
        self.mapper.addMapping(
            self.coffee_brand,
            coffees_model.fieldIndex('coffee_brand')
        )
        self.mapper.addMapping(
            self.coffee_name,
            coffees_model.fieldIndex('coffee_name')
        )
        self.mapper.addMapping(
            self.roast,
            coffees_model.fieldIndex('description')
        )
```

`addMapping()`方法接受两个参数：一个小部件和一个模型列编号。我们使用模型的`fieldIndex()`方法通过名称检索这些列编号，但是您也可以在这里直接使用整数。

在我们可以使用我们的组合框之前，我们需要用选项填充它。为此，我们需要从我们的关系模型中检索`roasts`模型，并将其传递给组合框：

```py
        roasts_model = coffees_model.relationModel(
            self.coffees_model.fieldIndex('description'))
        self.roast.setModel(roasts_model)
        self.roast.setModelColumn(1)
```

`relationalModel()`方法可用于通过传递字段编号从我们的`coffees_model`对象中检索单个表模型。请注意，我们通过请求`description`的字段索引而不是`roast_id`来检索字段编号。在我们的关系模型中，`roast_id`已被替换为`description`。

虽然咖啡列表`QTableView`可以同时显示所有记录，但是我们的`CoffeeForm`设计为一次只显示一条记录。因此，`QDataWidgetMapper`具有*当前记录*的概念，并且只会使用当前记录的数据填充小部件。

因此，为了在我们的表单中显示数据，我们需要控制映射器指向的记录。`QDataWidgetMapper`类有五种方法来浏览记录表：

| 方法 | 描述 |
| --- | --- |
| `toFirst()` | 转到表中的第一条记录。 |
| `toLast()` | 转到表中的最后一条记录。 |
| `toNext()` | 转到表中的下一条记录。 |
| `toPrevious()` | 返回到上一个记录。 |
| `setCurrentIndex()` | 转到特定的行号。 |

由于我们的用户正在选择列表中的任意咖啡进行导航，我们将使用最后一个方法`setCurrentIndex()`。我们将在我们的`show_coffee()`方法中使用它，如下所示：

```py
    def show_coffee(self, coffee_index):
        self.mapper.setCurrentIndex(coffee_index.row())
```

`setCurrentIndex()`接受一个与模型中的行号对应的整数值。请注意，这与我们在应用程序的先前版本中使用的咖啡`id`值不同。在这一点上，我们严格使用模型索引值。

现在我们有了工作中的`CoffeeForm`，让我们在`MainView`中创建一个，并将其连接到我们咖啡列表的信号：

```py
        self.coffee_form = CoffeeForm(
            self.coffees_model,
            self.reviews_model
        )
        self.stack.addWidget(self.coffee_form)
        self.coffee_list.doubleClicked.connect(
            self.coffee_form.show_coffee)
        self.coffee_list.doubleClicked.connect(
            lambda: self.stack.setCurrentWidget(self.coffee_form))
```

由于我们使用索引而不是行号，我们可以直接将我们的`doubleClicked`信号连接到表单的`show_coffee()`方法。我们还将它连接到一个 lambda 函数，以将当前小部件更改为表单。

在这里，让我们继续创建一个工具栏操作来返回到列表：

```py
toolbar.addAction("Back to list", self.show_list)
```

相关的回调看起来是这样的：

```py
def show_list(self):
    self.coffee_list.resizeColumnsToContents()
    self.coffee_list.resizeRowsToContents()
    self.stack.setCurrentWidget(self.coffee_list)
```

为了适应在`CoffeeForm`中编辑时可能发生的数据可能的更改，我们将调用`resizeColumnsToContents()`和`resizeRowsToContents()`。然后，我们只需将堆栈小部件的当前小部件设置为`coffee_list`。

# 过滤数据

在这个应用程序中，我们需要处理的最后一件事是咖啡表单的评论部分：

1.  记住，评论模型是`QSqlTableModel`，我们将其传递给`CoffeeForm`构造函数。我们可以很容易地将它绑定到`QTableView`，就像这样：

```py
        self.reviews = qtw.QTableView()
        self.layout().addRow(self.reviews)
        self.reviews.setModel(reviews_model)
```

1.  这在我们的表单中添加了一个评论表。在继续之前，让我们解决一些视图的外观问题：

```py
        self.reviews.hideColumn(0)
        self.reviews.hideColumn(1)
        self.reviews.horizontalHeader().setSectionResizeMode(
            4, qtw.QHeaderView.Stretch)
```

表格的前两列是`id`和`coffee_id`，这两个都是我们不需要为用户显示的实现细节。代码的最后一行导致第四个字段（`review`）扩展到小部件的右边缘。

如果你运行这个，你会看到我们这里有一个小问题：当我们查看咖啡的记录时，我们不想看到*所有*的评论在表中。我们只想显示与当前咖啡产品相关的评论。

1.  我们可以通过对表模型应用**过滤器**来实现这一点。在`show_coffee()`方法中，我们将添加以下代码：

```py
        id_index = coffee_index.siblingAtColumn(0)
        self.coffee_id = int(self.coffees_model.data(id_index))
        self.reviews.model().setFilter(f'coffee_id = {self.coffee_id}')
        self.reviews.model().setSort(3, qtc.Qt.DescendingOrder)
        self.reviews.model().select()
        self.reviews.resizeRowsToContents()
        self.reviews.resizeColumnsToContents()
```

我们首先从我们的咖啡模型中提取选定的咖啡的`id`号码。这可能与行号不同，这就是为什么我们要查看所选行的第 0 列的值。我们将它保存为一个实例变量，因为以后可能会用到它。

1.  接下来，我们调用评论模型的`setFilter()`方法。这个方法接受一个字符串，它会被直接附加到用于从 SQL 表中选择数据的查询的`WHERE`子句中。同样，`setSort()`将设置`ORDER BY`子句。在这种情况下，我们按评论日期排序，最近的排在前面。

不幸的是，`setFilter()`中没有办法使用绑定变量，所以如果你想插入一个值，你必须使用字符串格式化。正如你所学到的，这会使你容易受到 SQL 注入漏洞的影响，所以在插入数据时要非常小心。在这个例子中，我们将`coffee_id`转换为`int`，以确保它不是 SQL 注入代码。

设置了过滤和排序属性后，我们需要调用`select()`来应用它们。然后，我们可以调整行和列以适应新的内容。现在，表单应该只显示当前选定咖啡的评论。

# 使用自定义委托

评论表包含一个带有日期的列；虽然我们可以使用常规的`QLineEdit`编辑日期，但如果我们能使用更合适的`QDateEdit`小部件会更好。与我们的咖啡列表视图不同，Qt 没有一个现成的委托可以为我们做到这一点。幸运的是，我们可以很容易地创建我们自己的委托：

1.  在`CoffeeForm`类的上面，让我们定义一个新的委托类：

```py
class DateDelegate(qtw.QStyledItemDelegate):

    def createEditor(self, parent, option, proxyModelIndex):
        date_inp = qtw.QDateEdit(parent, calendarPopup=True)
        return date_inp
```

委托类继承自`QStyledItemDelegate`，它的`createEditor()`方法负责返回将用于编辑数据的小部件。在这种情况下，我们只需要创建`QDateEdit`并返回它。我们可以根据需要配置小部件；例如，在这里我们启用了日历弹出窗口。

请注意，我们正在传递`parent`参数——这很关键！如果你不明确传递父小部件，你的委托小部件将弹出在它自己的顶层窗口中。

对于我们在评论表中的目的，这就是我们需要改变的全部内容。在更复杂的场景中，可能需要覆盖一些其他方法：

+   +   `setModelData()`方法负责从小部件中提取数据并将其传递给模型。如果需要在模型中更新之前将小部件的原始数据转换或准备好，你可能需要覆盖这个方法。

+   `setEditorData()`方法负责从模型中检索数据并将其写入小部件。如果模型数据不适合小部件理解，你可能需要重写这个方法。

+   `paint()`方法将编辑小部件绘制到屏幕上。你可以重写这个方法来构建一个自定义小部件，或者根据数据的不同来改变小部件的外观。如果你重写了这个方法，你可能还需要重写`sizeHint()`和`updateEditorGeometry()`来确保为你的自定义小部件提供足够的空间。

1.  一旦我们创建了自定义委托类，我们需要告诉我们的表视图使用它：

```py
        self.dateDelegate = DateDelegate()
        self.reviews.setItemDelegateForColumn(
            reviews_model.fieldIndex('review_date'),
            self.dateDelegate)
```

在这种情况下，我们创建了一个`DateDelegate`的实例，并告诉`reviews`视图在`review_date`列上使用它。现在，当你编辑评论日期时，你会得到一个带有日历弹出窗口的`QDateEdit`。

# 在表视图中插入自定义行

我们要实现的最后一个功能是在我们的评论表中添加和删除行：

1.  我们将从一些按钮开始：

```py
        self.new_review = qtw.QPushButton(
            'New Review', clicked=self.add_review)
        self.delete_review = qtw.QPushButton(
            'Delete Review', clicked=self.delete_review)
        self.layout().addRow(self.new_review, self.delete_review)
```

1.  删除行的回调足够简单：

```py
    def delete_review(self):
        for index in self.reviews.selectedIndexes() or []:
            self.reviews.model().removeRow(index.row())
        self.reviews.model().select()
```

就像我们在`MainView.coffee_list`中所做的一样，我们只需遍历所选的索引并按行号删除它们。

1.  添加新行会出现一个问题：我们可以添加行，但我们需要确保它们设置为使用当前选定的`coffee_id`。为此，我们将使用`QSqlRecord`对象。这个对象代表了来自`QSqlTableModel`的单行，并且可以使用模型的`record()`方法创建。一旦我们有了一个空的`record`对象，我们就可以用值填充它，并将其写回模型。我们的回调从这里开始：

```py
    def add_review(self):
        reviews_model = self.reviews.model()
        new_row = reviews_model.record()
        defaults = {
            'coffee_id': self.coffee_id,
            'review_date': qtc.QDate.currentDate(),
            'reviewer': '',
            'review': ''
        }
        for field, value in defaults.items():
            index = reviews_model.fieldIndex(field)
            new_row.setValue(index, value)
```

首先，我们通过调用`record()`从`reviews_model`中提取一个空记录。这样做很重要，因为它将被预先填充所有模型的字段。接下来，我们需要设置这些值。默认情况下，所有字段都设置为`None`（SQL `NULL`），所以如果我们想要默认值或者我们的字段有`NOT NULL`约束，我们需要覆盖这个设置。

在这种情况下，我们将`coffee_id`设置为当前显示的咖啡 ID（我们保存为实例变量，很好对吧？），并将`review_date`设置为当前日期。我们还将`reviewer`和`review`设置为空字符串，因为它们有`NOT NULL`约束。请注意，我们将`id`保留为`None`，因为在字段上插入`NULL`将导致它使用其默认值（在这种情况下，将是自动递增的整数）。

1.  设置好`dict`后，我们遍历它并将值写入记录的字段。现在我们需要将这个准备好的记录插入模型：

```py
        inserted = reviews_model.insertRecord(-1, new_row)
        if not inserted:
            error = reviews_model.lastError().text()
            print(f"Insert Failed: {error}")
        reviews_model.select()
```

`QSqlTableModel.insertRecord()`接受插入的索引（`-1`表示表的末尾）和要插入的记录，并返回一个简单的布尔值，指示插入是否成功。如果失败，我们可以通过调用`lastError().text()`来查询模型的错误文本。

1.  最后，我们在模型上调用`select()`。这将用我们插入的记录重新填充视图，并允许我们编辑剩下的字段。

到目前为止，我们的应用程序已经完全功能。花一些时间插入新的记录和评论，编辑记录，并删除它们。

# 总结

在本章中，你学习了关于 SQL 数据库以及如何在 PyQt 中使用它们。你学习了使用 SQL 创建关系数据库的基础知识，如何使用`QSqlDatabase`类连接数据库，以及如何在数据库上执行查询。你还学习了如何通过使用`QtSql`中可用的 SQL 模型视图类来构建优雅的数据库应用程序，而无需编写 SQL。

在下一章中，你将学习如何创建异步应用程序，可以处理缓慢的工作负载而不会锁定你的应用程序。你将学习如何有效地使用`QTimer`类，以及如何安全地利用`QThread`。我们还将介绍使用`QTheadPool`来实现高并发处理。

# 问题

尝试这些问题来测试你对本章的了解：

1.  编写一个 SQL`CREATE`语句，用于创建一个用于保存电视节目表的表。确保它有日期、时间、频道和节目名称的字段。还要确保它有主键和约束，以防止无意义的数据（例如同一频道上同时播放两个节目，或者没有时间或日期的节目）。

1.  以下 SQL 查询返回语法错误；你能修复吗？

```py
DELETE * FROM my_table IF category_id == 12;
```

1.  以下 SQL 查询不正确；你能修复吗？

```py
INSERT INTO flavors(name) VALUES ('hazelnut', 'vanilla', 'caramel', 'onion');
```

1.  `QSqlDatabase`的文档可以在[`doc.qt.io/qt-5/qsqldatabase.html`](https://doc.qt.io/qt-5/qsqldatabase.html)找到。了解如何使用多个数据库连接；例如，对同一数据库创建一个只读连接和一个读写连接。你将如何创建两个连接并对每个连接进行特定查询？

1.  使用`QSqlQuery`，编写代码将`dict`对象中的数据安全地插入到`coffees`表中：

```py
data = {'brand': 'generic', 'name': 'cheap coffee',
    'roast': 'light'}
# Your code here:
```

1.  你创建了一个`QSqlTableModel`对象并将其附加到`QTableView`。你知道表中有数据，但在视图中没有显示。查看代码并决定问题出在哪里：

```py
flavor_model = qts.QSqlTableModel()
flavor_model.setTable('flavors')
flavor_table = qtw.QTableView()
flavor_table.setModel(flavor_model)
mainform.layout().addWidget(flavor_table)
```

1.  以下是附加到`QLineEdit`的`textChanged`信号的回调函数。解释为什么这不是一个好主意：

```py
def do_search(self, text):
    self.sql_table_model.setFilter(f'description={text}')
    self.sql_table_model.select()
```

1.  你决定在咖啡列表的“烘焙”组合框中使用颜色而不是名称。你需要做哪些改变来实现这一点？

# 进一步阅读

查看以下资源以获取更多信息：

+   SQLite 中使用的 SQL 语言指南可以在[`sqlite.org/lang.html`](https://sqlite.org/lang.html)找到

+   可以在[`doc.qt.io/qt-5/qtsql-index.html`](https://doc.qt.io/qt-5/qtsql-index.html)找到`QtSQL`模块及其使用的概述
