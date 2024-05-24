# ImpactJS HTML5 游戏开发（三）

> 原文：[`zh.annas-archive.org/md5/441DA316F62E4350E9115A286AB618B0`](https://zh.annas-archive.org/md5/441DA316F62E4350E9115A286AB618B0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：音乐和音效

音乐和音效就像蛋糕上的樱桃：当正确实施时，它们可以极大地改善游戏体验，但如果没有，至少你还有蛋糕。现在的大预算游戏总是伴随着原创和精美的歌曲和曲调。游戏音乐领域在过去几十年里已经发展壮大，有许多作曲家致力于制作游戏音乐。

以下是一些伟大作曲家的名单：

+   近藤浩治（马里奥和塞尔达系列）

+   植松伸夫（《最终幻想系列》）

+   中村正人（索尼克、合金装备固、《银河战士 Prime》系列）

+   迈克尔·贾奇诺（《使命召唤》、《荣誉勋章：联合突击》）

+   比尔·布朗（《命令与征服将军》、《敌领土》、《彩虹六号》）

+   杰瑞米·索尔（《上古卷轴》系列、《星球大战：旧共和国》、《全面毁灭》、《无冬之夜》、《博德之门》、《公会战争》、《英雄连》、《普特普特》）

这些人确实知道如何制作令人惊叹的音乐，为游戏体验增添了难以置信的附加值。这些游戏中使用的曲调通常变得与游戏本身一样具有标志性和令人难忘。如果你观看一部非常古老的电影，你会注意到它们使用的音乐和音效要比现在少得多，这使得它们对我们许多人来说几乎无法观看。尝试从任何最近的电影中剥离所有的背景音乐，你可能会发现它看起来乏味，即使故事内容保持不变。对于许多游戏来说也是如此，特别是对于冒险游戏来说，精心谱写的背景音乐非常重要，因为它有助于将你带入故事情节中。

同样，没有音效和威胁性音乐的恐怖游戏几乎是不可想象的。曲调和音效对于营造场景的氛围至关重要。一个很好的例子是著名的游戏《生化危机》。在这款僵尸游戏中，即使 20 分钟内什么都没有发生，你仍然会时刻保持警惕。正是声音和威胁性的音乐让你本能地不愿意打开下一扇门。因此，在选择音乐和音效之前，考虑一下你希望玩家在玩游戏时产生的感觉。对于唤起感觉来说，没有什么比完美选择的音乐和声音更有影响力了。

在本章中，我们将看一下一些游戏音乐的来源，除了这些相当昂贵的作曲家。我们将简要介绍一下 FL Studio，它可以用来创作你自己的音乐。最后，我们将在 ImpactJS 中整合音乐和音效。

# 制作或购买音乐

如果你决定要为你的游戏添加一些音乐，问题仍然是要么自己制作，要么购买。似乎作为一个 2D 游戏开发者，你需要了解一点点所有的东西：你必须能够理解游戏心理学，实际编写游戏程序，为其制作图形，甚至创作其音乐。听起来你需要成为一个全能的人才才能完成这样的壮举。然而，在图形设计和音乐领域进行教育可能是浪费时间。虽然成为一个通才是一个很好的特点，但考虑一下为你的游戏创作音乐需要多少时间，而不是从别人那里购买。

在本章中，这两种选择都得到了支持。首先，让我们看看一些可以为你提供音乐和音效的网站。

# 购买曲调和音效

如果你需要一些游戏音乐，你可以像杰瑞米·索尔一样雇佣一位个人作曲家。然而，假设你没有数百万美元的预算，以下网站可能会有所帮助：

[www.craze.se](http://www.craze.se)

在*Craze*上，可以找到各种类型的音乐。这些歌曲可以提前听，并且价格从每首 15 美元到 60 美元不等。它们也可以作为包购买，这将大大降低总成本。

如果你正在寻找一个价格相对更实惠的供应商，你可以看看以下链接中的*Lucky Lion Studios*：

[www.luckylionstudios.com](http://www.luckylionstudios.com)

大多数曲目售价为 5 美元。他们接受定制委托，并且甚至会区分购买定制项目的独家或非独家权利，从而让您在定制任务上节省成本。

最后，如果您正在寻找一些免费音乐，可以在以下链接找到*Nosoapradio*：

[www.nosoapradio.us](http://www.nosoapradio.us)

这个网站拥有一切；您可以随意收听和下载超过 300 首曲目（超过 12 小时的音乐），而且完全免费使用。该网站甚至提供了一个种子文件的追踪器，让您一次性下载 1GB 的音乐。这是一个很棒的网站，如果您希望有一些音乐作为占位符，甚至发布一个真正的游戏。

还有一些网站可以购买音效：

+   *Pro sound effects*允许您以每个效果 5 美元的价格从各种不同的声音中购买，链接如下：

[www.prosoundeffects.com](http://www.prosoundeffects.com)

您还可以购买特定主题的整个音效库，例如动物声音。这些套餐的价格范围可以从 40 美元到 15000 美元不等。

+   *Radish patch*每小时以 45 美元的价格提供定制工作，还以 8 美元或 80 美元的价格出售预制音效，具体取决于您的计划。链接如下：

[www.radish-patch.com](http://www.radish-patch.com)

如果您计划销售超过 5000 份游戏，他们将收取每个音效 80 美元，而不是 8 美元。

+   列表中还有一个免费网站供您使用，链接如下：

[www.mediacollege.com/downloads/sound-effects/](http://www.mediacollege.com/downloads/sound-effects/)

*Media college*提供了大量免费的声音效果，涵盖了各种主题。他们唯一要求的是，如果您喜欢他们提供的内容，可以捐赠一些费用。

与优质音乐不同，音效并不难制作。您只需要一个所需声音的列表，一个体面的录音机，一点空闲时间（也许还有一些疯狂的朋友来帮助您制作）。因此，在决定是自己制作还是购买音效时，建议自己制作，除非您需要一些真正优质的效果。

现在让我们来看看 FL Studio 的基础知识。

# 使用 FL Studio 制作基本曲调

**FL Studio**是一款数字音频工作站，以前被称为 FruityLoops。以下是 FL Studio 的标志：

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_1.jpg)

FL Studio 不是免费软件，而是一个可以从他们的网站下载的演示版本：

[www.fl-studio.en.softonic.com](http://www.fl-studio.en.softonic.com)

FL Studio 被认为是目前最完整的虚拟工作室。但是，FL Studio 目前尚不适用于 Linux。

对于 Linux 用户，**LMMS**可能是一个不错的（免费）但功能较弱的替代品。以下是 LMMS 的标志：

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_2.jpg)

您可以从以下链接下载 LMMS：

[`lmms.sourceforge.net/download.php`](http://lmms.sourceforge.net/download.php)

由于本书的目的不是深入了解音乐制作，因此这里只涵盖了 FL Studio 的基础知识。

打开 FL Studio 时，首先注意到的是顶部菜单栏，如下面的截图所示：

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_3.jpg)

我们大致可以区分三个主要部分。在左侧是您可以期望任何程序都具有的所有菜单：**文件**，**工具**，**视图**，**选项**等。栏的中间提供了快速访问播放、停止和其他与您正在处理的歌曲直接相关的按钮。在右侧，我们可以找到一些快速访问按钮，用于 FL Studio 的重要元素。

创建新文件时，FL Studio 允许您从模板开始，这对于初学者来说非常方便。

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_4.jpg)

例如，**Basic with limiter**将立即为用户提供鼓线的不同元素。这样，您就不需要自己找出基本组件。FL Studio 的五个最重要的元素的快速访问按钮从左到右依次是：播放列表、步进序列器、钢琴卷、文件浏览器和混音器，如下面的屏幕截图所示：

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_5.jpg)

如果您打开步进序列器，您会注意到您的第一个序列**Pattern 1**已经预定义了四个元素：**Kick**、**Clap**、**Hat**和**Snare**。如下列表所述，这四个元素构成了您鼓线的基础。

+   **Kick**可以比作您的大鼓。

+   **Clap**是拍子的近似。Clap（也称为 tala）本身是印度古典音乐中用于任何作品的节奏模式的术语。

+   **Snare**代表较小的鼓。

+   **Hat**是您鼓线的钹。

以下屏幕截图显示了**Pattern 1**序列：

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_6.jpg)

在您的模式中，每个乐器都有一系列矩形。通过单击一个矩形，您告诉 FL Studio 在该特定点激活这个乐器。右键单击突出显示的矩形将再次关闭它。FruityLoop studio 中的几乎所有内容都是通过左键单击打开或添加的，而右键单击用于关闭或删除。尝试通过在特定时间间隔激活一些乐器来制作出声音不错的鼓线。

创建了一个模式后，可以将其添加到播放列表。**播放列表**控制台将保存项目中所有音乐的所有部分，如下面的屏幕截图所示：

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_7.jpg)

您的所有模式可以根据您使用它们的方式同时或顺序地进行排队或播放。在**播放列表**控制台中左键单击一个位置，基本上是在该位置*绘制*一个模式。右键单击一个模式将其删除。要更改模式，您当前正在放置的下拉框位于**播放列表**控制台的右上角。

FL Studio 为用户提供了各种乐器、音效，甚至预制音乐和一些语音效果，如下面的屏幕截图所示：

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_8.jpg)

所有这些资源都可以通过**文件浏览器**访问。从这里，您可以向您的序列构建器添加乐器，例如合成器或吉他。每种声音类型都有不同的符号，如下面的屏幕截图所示，甚至可以在浏览器中预览（或提前听到）预制音乐：

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_9.jpg)

添加预先编排的旋律可以让您快速制作出一首相当不错的歌曲，然后可以将其合并到您的游戏中。

如果您已经向您的序列构建器添加了乐器，比如合成器，请尝试打开其**钢琴卷**控制台，如下面的屏幕截图所示：

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_10.jpg)

**钢琴卷**控制台允许您定义乐器需要演奏的每个音符。对于一些乐器，比如鼓，这并不总是必要的，但对于其他乐器来说，绝对建议在**钢琴卷**控制台中制作自己的小曲调。您可以在与鼓线相同的模式中进行，或者您可以开始一个不同的模式，在那里释放您的创造力，如下面的屏幕截图所示：

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_11.jpg)

最终，您创建的每一首音乐都应该最终进入播放列表。使用不同的音轨是保持对同时发生的所有事情的良好视图的关键。如果您忘记将不同的乐器类别分配到不同的音轨中，不用担心，在**播放列表**窗口中有一个拆分它们的选项。

在某个时候，您会想要听听您的不同音轨一起播放时的声音。为此，您需要从模式切换到**歌曲**模式，如下图所示：

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_12.jpg)

如果您觉得需要对不同的乐器进行一些额外的调整，这就是**混音器**控制台发挥作用的地方。**混音器**控制台允许您更改音量、平衡和特殊效果，如下图所示：

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_13.jpg)

向音乐添加特殊效果或滤镜可以快速为您提供所需的额外触感。有许多预设的滤镜可供选择，它们都可以单独进行调整。如果您正在寻找一个快速解决方案，当然可以将它们保留在默认设置并进行操作。

在这四个元素中的每一个：序列器、播放列表、钢琴卷、和混音器中，都有一些模板和/或默认设置可用。如果您不想花太多精力来创建自己的音乐，请务必寻找这些。您可以使用已经存在的内容，稍作调整，很快就可以拥有自己的配乐！

当您完成第一首歌曲时，您可能不仅想要保存它，还想将其导出为`.mp3`和`.ogg`文件。

![使用 FL Studio 制作基本曲调](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_6_14.jpg)

同样，不要忘记将项目切换到歌曲模式，而不是模式模式，否则您只会导出当前选择的模式。

一旦歌曲被导出，您可以在 ImpactJS 中使用您刚刚创建的内容。

# 将背景音乐添加到您的游戏中

背景音乐是您希望始终播放的东西。很多游戏会在情况变得艰难时，将音乐从平静变为更加热烈的音轨。所有这些都可以使用`if`条件来在您的主代码中或专门用于管理播放列表的单独文件中完成。

ImpactJS 有两个重要的类负责您想要使用的所有声音：`ig.music`和`ig.sound`。`ig.music`是我们需要的背景音乐。假设您想要将您的音乐添加到第三章的项目中，*让我们建立一个角色扮演游戏*或第四章的项目中，*让我们建立一个横向卷轴游戏*。将以下代码添加到`main.js`中`MyGame`定义的`init()`函数中：

```js
init: function() {
  this.loadLevel(LevelLevel1);
  ig.input.bind(ig.KEY.UP_ARROW, 'up');
  ig.input.bind(ig.KEY.DOWN_ARROW,'down');
  ig.input.bind(ig.KEY.LEFT_ARROW,'left');
  ig.input.bind(ig.KEY.RIGHT_ARROW,'right');
  ig.input.bind(ig.KEY.MOUSE1,'attack');
  var music = ig.music;
  music.add("media/music/background.*");
  music.volume = 1.0;
  music.play();
},
```

请注意，我们将我们的歌曲添加为`background.*`，而不是`background.ogg`或`background.mp3`。这样游戏就知道它需要查找所有名为`background`的文件，而不管它们的扩展名是什么。由于我们在`media`文件夹中创建了一个单独的`music`文件夹，这里不应该有命名冲突。使用`background.*`不仅方便（一行代码而不是两行），而且对于系统使用`music`文件也是有帮助的。有时这将是`.mp3`，有时是`.ogg`；至少现在可以自动确定要使用的`music`文件。Chrome 现在似乎更喜欢 WebM 而不是`.mp3`或`.ogg`，但仍然可以使用`.mp3`和`.ogg`。另一方面，Firefox 更喜欢使用`.ogg`，而不使用`.mp3`。

`ig.music`本身就是一种播放列表，具有多个功能。使用`add()`方法将在播放列表的末尾添加另一首歌曲。您可以用几乎无限数量的歌曲填充这个列表。`music.volume`方法设置了您的歌曲音量，范围从`0`到`1`。`music.play()`方法将激活播放列表中的第一首歌曲。前面的代码不仅会激活您的歌曲，而且会无限循环播放，因为这是默认设置。除了简单启动循环的方法之外，还有许多其他函数。

`fadeout(time)`将使您的歌曲在您指定的时间内淡出。当歌曲的音量达到`0`时，它将调用`stop()`方法，停止歌曲的播放。在 ImpactJS 中有您在常规收音机上期望的一切。您可以使用`pause()`和`next()`方法，以及`loop`和`random`属性使歌曲循环和随机播放。另一个有趣的属性是`currentIndex`，因为它将返回当前播放歌曲在播放列表中的位置。这在管理歌曲顺序并在必要时切换歌曲时非常有用。

# 当发生某个动作时播放声音

`ig.music`非常适合用于音乐，因为它与基本媒体播放器有许多共同的功能。对于播放音乐，`ig.music`是最佳选择，而对于播放音效，您应该使用`ig.sound`以获得最佳效果。

声音效果并不是持续活动的，而是只在执行某些动作时发生。比如说，当玩家发射抛射物时，我们希望听到枪声。我们需要在玩家的`init()`方法中添加声音，这样它就可以作为资源使用。

在`player.js`中使用以下代码添加`this.gunshotsound`：

```js
init: function( x, y, settings ) {
  this.parent( x, y, settings );
  // Add the animations
  this.addAnim( 'idle', 1, [0] );
  this.addAnim('down',0.1,[0,1,2,3,2,1,0]);
  this.addAnim('left',0.1,[4,5,6,7,6,5,4]);
  this.addAnim('right',0.1,[8,9,10,11,10,9,8]);
  this.addAnim('up',0.1,[12,13,14,15,14,13,12]);
  //set up the sound
  this.gunshotsound = new ig.Sound('media/sounds/gunshot.*');
  this.gunshotsound.volume = 1;
},
```

然后，通过在`player.js`中添加以下代码，我们实际上播放了抛射物发射时的声音。

```js
if(ig.input.pressed('attack')) {
  if (GameInfo.projectiles> 0){
    ig.game.spawnEntity('EntityProjectile',this.pos.x,this.pos.y,{direction:this.lastpressed});
    ig.game.substractProjectile();
    this.gunshotsound.play();
  }
}
```

在`ig.music`中，歌曲被添加到播放列表中，声音是通过调用`ig.sound`的新实例来启动的。当只有一首歌曲被添加到音乐播放列表时，默认情况下它会永远循环。这对于使用`ig.sound`启动的音效并不适用，因为它没有`loop`属性，因此在调用`.play()`方法时，声音只会播放一次。`ig.sound`具有`.enabled`属性，默认设置为`true`。将其设置为`false`将为游戏停用所有声音和音乐。这很有用，因为一些移动设备在需要同时播放两种不同的声音时仍然存在问题。同时播放两种不同的声音是非常常见的，特别是如果您已经在播放背景音乐。通过使用 Ejecta，ImpactJS 的直接画布解决方案，可以解决这个问题。代码保持不变，但是 Ejecta 目前只支持 iPhone 和 iPad，不支持 Android 或 Windows 设备。

# 在游戏中使用声音文件的技巧

优化声音文件意味着保持简短和简单。大多数游戏都有短小的歌曲，不会太过于显眼，因此不会总是被注意到。即使不被注意到的歌曲仍然会影响情绪，而且不会显得太过重复。为了优化目的，有一些事情您一定要注意：

+   保持歌曲简短，并且只在需要时将其加载到内存中。

+   准备相同的歌曲，分别以`.ogg`和`.mp3`格式，这样需要播放的系统可以选择最有效的扩展名。

+   使用以下代码在目标发布游戏的移动设备上双重检查您的声音是否有效。如果没有，请确保在这些设备上关闭所有声音，直到能够使声音在这些设备上正常工作为止。

```js
if(ig.ua.mobile){
  ig.music.add("media/music/backgroundMusic.ogg");
  ig.music.play();
}
```

+   这不仅仅是一种优化，更是一种用户友好的措施，但请确保允许玩家关闭音乐和音效。最好是分开两者：有些玩家喜欢听枪声，但不喜欢你的音乐。如果你使用游戏分析，请确保跟踪这些变化，以便了解哪种类型的歌曲是可以接受的，哪种是不可以接受的。

# 总结

在本章中，我们讨论了音乐和音效作为在游戏中营造氛围的重要元素。我们讨论了是否应该购买或创建音乐以及你可以在哪里找到它：免费或付费。我们使用 FL Studio 创建了自己的基本背景音乐，并将其添加到了我们的游戏中。最后，我们总结了在 ImpactJS 中使用音乐的一些建议。

在下一章中，我们将看一下图形。我们将检查是购买还是制作它们更好，以及如何使用 Inkscape 或 Photoshop 创建图形。


# 第七章：图形

你可以有完美运行的脚本，但如果没有东西可看，就没有游戏。图形很重要，我们将在这里探讨如何获得它们并在 ImpactJS 中实现它们。在本章中，你将学到：

+   不同类型的图形

+   在决定是制作还是购买图形时你应该考虑什么

+   如何使用免费工具 Inkscape 制作矢量图形

+   如何利用 Adobe Photoshop 将现实变成游戏

自数字游戏开始以来，游戏图形一直在不断发展。快速浏览一下《太空战争！》及其街机版本《计算机空间》，《乒乓球》，《枪战》，以及许多其他古老的游戏。你会注意到的第一件事不是游戏玩法的不同，而是缺乏图形的华丽。更快的计算机和专用图形处理器的发展使得游戏变得越来越漂亮。当然，有一个普遍的趋势朝着更多的现实主义发展：我们能让游戏看起来多像现实生活而不会把我们的处理器烧毁？这有点像绘画的发展。画家们倾向于追求更多的细节，更好地逼近现实生活中所见的东西。这是一个挑战，直到他们开始使用光学透镜将图像直接反射到画布上。然后他们只需要描绘和上色。艺术家们开始寻找在画布上表达自己的新方法，因为完美不再是成功的保证。几个世纪后，当图形完美达到时，世界看到了像毕加索的《格尔尼卡》和爱德华·蒙克的《尖叫》这样的绘画。这两者都远非接近完美的现实主义；但它们都有一些东西能吸引人们。

在游戏世界中似乎正在发生类似的事情。最近的游戏已经证明我们可以非常接近现实，一些游戏开发者已经开始寻找更原创的外观。例如，任天堂从未努力接近提供逼真的图形，但他们在制作优秀游戏方面的技能在全世界都受到尊敬。这是因为他们明白，在玩家心中激起某种感觉比展示玩家从屏幕上看到的东西更重要。

看看 1995 年发行的超级任天堂游戏《耀西岛》。这里描绘的场景远非现实。然而，只要玩上 10 分钟，你就会充满快乐的感觉。一切看起来都是如此快乐和闪闪发光，色彩明亮而快乐。当它们不打算杀死你时，动物甚至云朵都会用真诚的快乐微笑着看着你。

《塞尔达传说：风之杖》于 2003 年发布，是最早使用卡通渲染图形的大型游戏之一。卡通渲染或卡通风格的图形看起来就像是手绘的。卡通渲染已经被许多其他非常成功的游戏使用，如《无主之地》和《大神》。

之前的例子是 3D 游戏，但你现在正在阅读这篇文章就证明了制作游戏并不仅仅是关于图形。许多年前，游戏成功地从 2D 过渡到 3D。即使我们心爱的马里奥也能够出色地完成这个过渡。3D 游戏通常被认为比 2D 游戏更令人愉悦。然而，你现在正在准备制作一个 2D 游戏。这证明了漂亮的图形对传达某种感觉很重要，但你可以以任何你希望的形式来传达这种感觉，就像艺术本身一样。

# 制作/购买图形

在制作游戏时，我们需要购买或制作自己的图形吗？我们至少有幸在这方面有选择。对于 3D 游戏，自己制作图形的选择通常受到开发团队规模的限制。对于 2D 游戏，自己完成所有工作的选择仍然是一个现实的选择。如果你没有预算购买精灵和瓷砖集，你有三个主要选项来创建你的图形：

+   像素艺术

+   矢量艺术

+   使用 Photoshop 创造现实

在这三个选项中，逐像素绘制你的角色和场景是最雄心勃勃的选择。优秀的艺术家可以用这种方法得到非常好的结果，但即使是最有经验的像素艺术家也会花费数小时来绘制几个角色和瓷砖集。有一些工具可以帮助你将自己的绘画技能转移到电脑上，比如数字绘画笔和软件：Adobe Photoshop 或其免费的对应物 GIMP。如果你对绘画没有任何经验，也没有强烈的冲动去投入精力学习，那就干脆不要尝试。

第二个选择是矢量图形设计。矢量图形与像素艺术不同，因为图形是由线条和基本形状构建而成，而不是单独的点。这些线条和形状可以自由缩放到更高或更低的分辨率，而对于像素艺术来说，这可能非常困难。从基本形状如矩形、圆形和线条构建图形需要一种不同于常规绘画的洞察力。制作图形的先决条件基本上是从需要稳定的手转变为对物体和生物的分析视角。以《愤怒的小鸟》中的鸟为例。它们的基本形状是一个圆，眼睛放在中心的圆形上。它们的喙略呈圆形三角形，它们的眉毛和尾巴只是一堆矩形。如果你从这种更分析的角度看这些愤怒的小鸟，那么自己画一个就会变得更容易。如果你觉得自己有一些分析洞察力，即使你的绘画技能只是普通水平，只要你付出足够的努力，你就可以制作自己的瓷砖集。本章将简要介绍如何做到这一点。

最后一个选择更像是一个快速解决方案。通过拍摄物体的照片并将其转换为瓷砖集，你可以迅速获得一些图形。虽然对于 3D 游戏来说，接近真实场景是非常困难的，但对于 2D 游戏来说，这实际上是最简单的方法。当然，这里的主要问题是，如果使用调整后的图片，你很难在竞争对手中脱颖而出，这在推广游戏时是一个真正的缺点。尽管如此，这些图形看起来很好，这是一种快速而廉价的获取图形的方式。

# 购买图形的地方

尽管 2D 游戏相当普遍，但并没有很多公司专门为业余游戏开发者提供瓷砖集。大多数游戏艺术家要么为游戏公司工作，要么按照客户的要求工作，这往往对于业余时间开发游戏的人来说太昂贵了。

然而，有一些价格实惠的 2D 游戏图形制作商，例如[www.sprites4games.com](http://www.sprites4games.com)。他们有一些免费的精灵可用，但他们尤其因其美丽而实惠的定制作品而备受赞誉。

从随机网页下载免费瓷砖集时，存在两个主要问题：

+   瓷砖集非常不完整，因此实际上无法用它们来创建整个游戏。

+   免费瓷砖集的另一个问题是它们实际上并不是免费的。它们经常是从现有游戏中剥离出来的，重新使用它们是违法的。

例如，在[www.spritedatabase.net](http://www.spritedatabase.net)，你可以下载整个游戏的瓷砖集。但实际上使用它们来发布你自己的游戏可能会导致因侵犯版权而被起诉。

有时你也可以在更大的艺术和照片网站上找到瓷砖集，比如[www.shutterstock.com](http://www.shutterstock.com)。问题在于混乱；在所有这些其他图片中找到实际的游戏图形是很困难的。如果你最终找到了一些，你将面临与免费瓷砖集相同的问题：不完整。在那时，你可以联系艺术家并请求更多的图形，但那又变成了定制工作，这往往会变得相当昂贵。

# 矢量图形介绍

现在我们已经看过了不同的选项，让我们深入了解其中一个：创建我们自己的矢量图形。有几种有趣的工具可以帮助你。Adobe Illustrator 是市场上最好的之一。然而，在这里我们将使用一个稍微不那么先进但免费的工具：Inkscape。你可以在他们的网站上下载 Inkscape：[www.inkscape.org/download/](http:// www.inkscape.org/download/)。

一旦我们在计算机上安装了 Inkscape，我们就可以开始制作一个机器人角色。

有几种方法可以绘制自己的角色或物体。真正的艺术家使用钢笔工具来完成，如下面的截图所示：

![矢量图形简介](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_3.jpg)

这是一个非常多才多艺的绘图工具，它使您能够绘制直线和最完美对称的曲线。然而，在这个简短的初学者教程中，我们将限制自己使用基本形状，如矩形和圆来构建我们的小机器人，如下图所示：

![矢量图形简介](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_4.jpg)

这实际上将是一个小机器人，因为我们希望它的大小与我们一直在使用的角色相同：48 x 32 像素。尽管矢量图形是可伸缩的，但最好还是按照要使用的比例来工作。在处理这些小分辨率时，实际上看到你要填充的像素是有意义的。您可以通过在“视图”选项卡下打开“网格”选项来实现这一点。此外，您需要在放大的图片和实际大小之间切换；这样你就可以看到你实际上要在游戏中放入多少细节。放大和缩小可以使用鼠标的 Ctrl 键和滚轮来完成；此外，通过按键盘上的“1”键，可以简单地以 1:1 的比例查看所有内容。

![矢量图形简介](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_5.jpg)

当我们看我们想要构建的机器人时，可以注意到一些重要的东西：头部被放大了。通常，人类的头部大小应该是人体的八分之一或七分之一。在低分辨率下绘制时，头部大约应该是身体大小的三分之一到一半。这是非常不现实的，但至少你能看到一些面部特征，比如眼睛和嘴巴。这种大头风格被称为千变，意思是日语中的“矮个子”；它非常适合小动画。

让我们首先看一下我们需要的基本形状。这似乎不过是一些矩形（圆角和普通的）和两个椭圆形的眼睛，如下面的截图所示：

![矢量图形简介](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_6.jpg)

矩形的角可以通过选择普通矩形并在下面的面板中更改其角的半径来轻松圆角，如下面的截图所示：

![矢量图形简介](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_7.jpg)

椭圆形只不过是一个拉长的圆。您可以在任何方向拉伸任何形状，并在必要时旋转或倾斜它，如下面的截图所示：

![矢量图形简介](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_8.jpg)

在处理矢量图形时，最好有不同的图层来处理不同的动画。例如，如果我们想让我们的机器人行走，我们需要它的一只胳膊和腿伸出，然后是另一只胳膊和腿。从动画的角度来看，将身体和手臂和腿放在单独的图层中是有意义的。身体的形状在移动时不会改变，而肢体的形状会改变。

现在我们有了基本的形式，让我们专注于颜色。在低分辨率下工作时，最好是有很大的对比度。你可以通过选择一个接近白色和一个接近黑色的颜色来实现这一点，从而调整亮度。或者，你可以选择使用两种互补颜色。当两种颜色互补时，它们是彼此的对立面，当它们相邻时产生最大的对比度。因此，在选择颜色时，引入色轮是有用的。在这个色轮上，彼此相对的颜色被认为是互补颜色。例如，黄色的补色是紫色，如下图所示：

![矢量图形介绍](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_9.jpg)

我们的机器人将是灰色和黑色。为了给它上色，我们只需要右键单击鼠标按钮，选择**填充和描边**，并用我们喜欢的颜色填充它。

![矢量图形介绍](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_10.jpg)

此外，我们可以通过在我们的圆圈中切换到不完整的弧线来给我们的机器人的眼睛增加一些额外的细节，使用下图中显示的面板。

![矢量图形介绍](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_11.jpg)

我们的机器人现在有了一个可识别的形式，甚至有了这个小眼睛细节。这些细节的问题在于，当实际玩游戏时，它们并不总是可见，如下图所示，我们的机器人角色的最小化形式；找到合适的细节量可能会有些棘手。

![矢量图形介绍](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_12.jpg)

我们可以像下图所示在他的头上加上天线，虽然很小，但仍然是可识别的；最终，这是你需要考虑的每一个细节。让我们在角色的下图所示的绘画中加入一点阴影。我们可以通过将填充改为渐变图案而不是均匀填充来实现这一点。

![矢量图形介绍](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_13.jpg)

此外，通过使用这些渐变阴影图案添加一些额外的形式，我们可以使设计看起来更加逼真。作为练习，你可以为角色空闲时添加自己的动画。例如，一个人会吸气和呼气，使他的胸部上下起伏。为了描绘这一点，你可以添加一张额外的图像，使游戏感觉更加生动。最终，我们得到了我们的最终机器人。教它如何行走只是把最好的一面展现出来，然后当然是另一面。如果你在一个图层中工作，可以通过选择它们并按下*Home*键将一条腿和一只胳膊移到前面来完成。按下*End*键将选定的手臂放在其他形式的后面。或者，你可以使用**对象**菜单来实现同样的事情。不过，理想情况下，你会希望使用不同的图层，因为这样会让生活变得更加容易。然而，在这里我们不会深入到那个层面的细节。

![矢量图形介绍](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_14.jpg)

机器人看起来好像要离开他的小画面，直接走向你，就像前面的图表所示的那样。要得到一个完整的角色，你至少需要为一个侧面视图和背面视图做同样的事情。一旦你有经验，这可以很快完成。然而，有一个更快的方法来获得图形。不过，你可能只想在图纸准备好之前使用它们作为占位符，这仍然是一个不错的选择。这个选择是使用 Adobe Photoshop 进行真实生活图片。

# 使用 Adobe Photoshop 创建你自己的头像

曾经梦想过在自己的游戏中四处走动吗？现在你可以了！你只需要一个相机和类似 Adobe Photoshop 的工具。虽然我们将使用 Adobe Photoshop，但市面上有很多免费的替代品可以胜任。甚至浏览器的解决方案也相当不错。Pixlr 就是一个很好的例子。它可以在[www.pixlr.com](http://www.pixlr.com)找到。

我们将从各个相关方向拍摄一堆照片开始。最好在均匀着色的屏幕前拍摄；简单的白色毯子或墙壁也可以。如果您的背景与您想捕捉的人容易区分，那么将他或她从图片中减去将更容易。我们可以使用快速选择工具来做到这一点，如下面的截图所示：

![使用 Adobe Photoshop 创建您自己的头像](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_15.jpg)

在将人与背景分离后，我们可以简单地将图片放入一个带有透明背景的新文件中，甚至可以添加一些效果，以赋予它更加超现实的触感，如下面的截图所示：

![使用 Adobe Photoshop 创建您自己的头像](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_16.jpg)

不要局限于 Adobe Photoshop 所提供的功能。有一些很好的网站可以以你难以想象的方式转换你的图片。其中一个网站是[www.befunky.com](http:// www.befunky.com)。

在这里，我们可以选择在我们的图片上释放卡通效果，使人几乎无法辨认，同时产生出这种漂亮的单色风格，如下面的截图所示：

![使用 Adobe Photoshop 创建您自己的头像](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_17.jpg)

您将不得不为所有的图片重复这个过程，这可能会耗费相当多的时间。然而，这比自己绘制它们要快得多。还要记住，被动对象只需要一张图片。需要实际动画表的游戏角色代表了大部分的工作量。

现在我们有了个人精灵，让我们来看看动画表本身。如果您没有适合的照片，现在是时候去让别人在白墙前拍几张照片了。在视频游戏中看到自己有点奇怪，所以试试看吧。

# 将您的作品添加到 RPG

为了从个人精灵到完全成熟的动画表中，所需做的就是将它们整齐地放在一个文件中。

![将您的作品添加到 RPG](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_7_18.jpg)

在开始之前，您需要考虑您的图片需要多大。在这个例子中，它们的尺寸为 32 x 96 像素。在早期章节中，我们的角色尺寸为 32 x 48 像素。拥有比我们当前示例拉伸得更少的图纸是更可取的，因为它们将使游戏玩起来更容易。操纵一个尺寸为圆形或正方形的角色要比操纵一个又长又细的角色容易得多。然而，在这种情况下，我们的测试人员又长又瘦，我们希望保持他的样子。

实际上，在单个动画表上安排图片是一项精密的工作，因此建议使用图片的坐标。Adobe Fireworks 在设置坐标时非常直观。任何图片程序都可以胜任；甚至可以在 MS Paint 中完成。当然还有其他选择。精灵表生成器将使排列精灵并将它们保存为瓷砖集合变得更加容易。您还可以选择在 Fireworks 中使用一些 JavaScript 排列代码来自动化定位过程。但是，这里不会对这些主题进行详细阐述。

当您最终设置好自己的表格时，就该将其引入游戏中了。将文件保存为`player.png`，并在之前章节中的代码和表格中进行替换。

```js
animSheet: new ig.AnimationSheet( 'media/player.png', 32, 96 ), 
init: function( x, y, settings ) {
  this.parent( x, y, settings );
  // Add the animations
  this.addAnim( 'idle', 1, [4] );
  this.addAnim('down',0.1,[3,4,3,5]);
  this.addAnim('left',0.1,[0,1,0,2]);
  this.addAnim('right',0.1,[6,7,6,8]);
  this.addAnim('up',0.1,[9,10,9,11]);
}
```

我们的动画序列非常短。对于每个视角，我们在静止和移动右腿或左腿之间切换。如果我们的角色是完全对称的，那么图表可能会更小。那样的话，我们只需要左右行走的动画，然后通过翻转图像来获得另一个动画，就像在前面的章节中所看到的那样。

# 在 HTML5 中使用图形的提示

为了结束本章，让我们回顾一下在 HTML5 中使用图形的一些要点：

+   尽量保持动画图表尽可能小。没有必要复制某些精灵；如果必要，动画序列允许多次引用同一个精灵。还要知道，每个浏览器都有不同的图像大小限制，尽管你必须相当粗心才能达到这个限制。

+   使用支持透明背景的文件格式。PNG 文件就可以胜任。JPG 无法保存透明背景，而会将其解释为纯白色。

+   尽量使用对称图形。这样你可以翻转图像，使角色从左到右行走，反之亦然，使用相同的图像。这也减少了你需要的精灵数量，从而减少了制作它们的工作量。

+   在 ImpactJS 中使用背景地图时，预渲染它们可能会很有用。背景地图与常规级别图层不同，它是通过您在脚本中提供的代码数组绘制的，而不是标准的 JSON 编码级别文件。这样就可以设置重复的背景。

```js
var backgroundarray= [
  [1,2,6],
  [0,3,5],
  [2,8,1],
];
var background = new ig.BackgroundMap( 32, backgroundarray,'media/grass.png' );
```

+   预渲染背景将使系统创建块，这是一组瓷砖。选择预渲染将需要更多的 RAM，因为需要将更大的块保留在内存中，但会加快绘图过程；这样设备的处理器上的负担就会减少。知道你有这个选项，并根据你认为 RAM 还是处理能力将成为瓶颈，你可以选择通过使用 ImpactJS 的`.prerender`属性来预渲染背景或不预渲染。此外，你可以设置块的大小来微调两种资源之间的平衡：

```js
background.preRender = true;
background.chunksize = 4096;
```

# 总结

图形是任何游戏的重要元素，因为它们是游戏所代表的一切的可视化。尽管游戏中的图形确实趋向于更加逼真，但这并不是获得良好游戏体验的绝对要求。我们讨论了是否应该制作或购买图形，以及在哪里可以以实惠的价格购买定制图形。如果决定创建自己的图形，我们区分了三个重要选项：像素图形、矢量图形，以及使用 Adobe Photoshop。跳过第一个选项，我们快速了解了如何使用 Inkscape 开发矢量图形，并使用 Adobe Photoshop 将自己添加到游戏中。本章以一些关于在游戏中使用图形的提示结束。在下一章中，我们终于可以向世界展示我们的游戏，因为我们将把它部署到从常规网站到 Google Play 等多个分发渠道。


# 第八章：调整您的 HTML5 游戏以适应分发渠道

当您的游戏终于准备好供全世界观看时，是时候考虑可能的分发渠道了。您想让人们在网站上的浏览器中玩游戏，还是作为 Web 应用程序？也许您希望他们在平板电脑或智能手机上玩游戏，无论是在浏览器中还是作为应用程序。在本章中，我们将探讨其中几种不同的选择以及成功实施所需的工作。

在本章中，您将学到：

+   为网络浏览器准备您的游戏

+   为移动网络浏览器做适应

+   将您的游戏发布为 Google Chrome 网络应用程序

+   将游戏转换为 Android 应用程序

+   使您的游戏在 Facebook 上可玩

+   实施 AppMobi 的直接画布

# 为网络浏览器准备您的游戏

在开发过程中，您一直在 Web 浏览器中测试您的游戏。那么您的本地服务器和公共或生产服务器之间有什么区别呢？

在向公众发布您的游戏之前，您需要对其进行烘烤。**烘烤**游戏不过是压缩代码。这有两个优点：

1.  压缩代码将比未压缩代码更快地加载到浏览器中。更短的加载时间总是一个很大的优势，特别是对于第一次玩您的游戏的人。这些人还不知道您的游戏有多棒，不想浪费时间看加载条。

1.  烘烤后的代码也更难阅读。所有不同的模块，整齐地排列在单独的文件中，现在都在一个文件中与 ImpactJS 引擎一起。这使得普通用户很难从浏览器中复制和粘贴你宝贵的源代码，然后在自己的游戏中使用。然而，这并不能防止那些真正知道自己在做什么的人；代码并没有加密，只是压缩了。

用您下载的 ImpactJS 引擎一起的烘烤游戏的工具。在游戏的`root`目录中的`tools`文件夹中，您应该有四个文件：`bake.bat`、`bake.php`、`bake.sh`和`jsmin.php`。按照以下步骤来烘烤您的游戏：

1.  用文本编辑器打开`bake.bat`文件，您会找到以下行：

```js
php tools/bake.php %IMPACT_LIBRARY% %GAME% %OUTPUT_FILE%
```

1.  将`php`更改为 XAMPP 或 WAMP 服务器中`php.exe`文件的目录。对于默认的 XAMPP 安装，这一行现在将如下所示：

```js
C:/xampp/php/php.exe tools/bake.php %IMPACT_LIBRARY% %GAME% %OUTPUT_FILE%
```

1.  保存并关闭`bake.bat`文件，然后双击运行它。在 Windows 上，一个命令窗口将打开，并且`game.min.js`脚本将被创建在游戏的`root`目录中，如下面的屏幕截图所示：![为网络浏览器准备您的游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_1.jpg)

`game.min.js`脚本现在包含了我们所有的代码。现在我们需要做的就是更改游戏`root`目录中的`index.html`文件，使其寻找`game.min.js`而不是`impact.js`和`main.js`脚本。

打开`index.html`文件，找到以下代码：

```js
<script type="text/javascript" src="img/impact.js"></script>
<script type="text/javascript" src="img/main.js"></script>
```

用我们新的紧凑版本的代码替换以前的代码，如下面的代码片段所示：

```js
<script type="text/javascript" src="img/game.min.js"></script>
```

现在，您可以剥离游戏文件夹中除`index.html`和`game.min.js`之外的所有代码文件，并将其上传到您的服务器。如果您购买了自己的网络空间，您可以使用免费的 FTP 程序，如**FileZilla**来完成此操作。

我们的游戏现在已经准备好分发了，通过将其加载到 Web 服务器，您已经可以让任何人使用。但是，我们还没有考虑移动设备上的浏览器。在我们研究这个问题之前，让我们快速回顾一下。

总结前面的内容，结论如下：

+   在向公众发布我们的游戏之前，我们应该对其进行烘烤。烘烤游戏基本上就是压缩源代码。烘烤有两个重要优点：

+   游戏加载到浏览器中的速度更快。

+   代码变得更难阅读，因此更不容易被盗。然而，代码并没有加密，因此对于一个专注的人来说，解除烘烤仍然相当容易。

+   为了烘烤游戏，我们在运行之前更改`bake.bat`文件。这个过程创建了一个`game.min.js`脚本。

+   在将游戏上传到服务器之前，我们在`index.html`文件中包含`game.min.js`而不是`main.js`和`impact.js`。

# 为移动 Web 浏览器准备我们的游戏

如果您考虑到人们可能使用智能手机玩游戏，您已经实现了触摸屏控制。这方面的例子可以在第五章中找到，*为您的游戏添加一些高级功能*。然而，有时这还不够。您希望玩家能够像在电脑上一样在智能手机上进行操作。为了实现这一点，我们可以引入**虚拟按钮**。这些虚拟按钮是屏幕上的区域，它们将表现得就像它们是常规键盘键一样。我们可以在`index.html`文件中使用**CSS**（层叠样式表）代码创建这些按钮。我们可以为玩家的每个动作创建按钮。在我们的角色扮演游戏中，他需要能够向各个方向行走和射击。在侧面卷轴游戏中，他可以向左或向右移动，飞行和射击。让我们假设我们将飞行与向上移动分开。以下屏幕截图显示了我们的按钮图块：

![为移动 Web 浏览器准备我们的游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_2.jpg)

以下是创建虚拟按钮的步骤：

1.  打开`index.html`文件，并在 canvas 的 CSS 代码下面添加以下代码。如果您使用的是 ImpactJS 引擎示例提供的`index.html`文件，则该文件应该已经包含 canvas 的以下样式代码。另外，第三章中的*让我们建立一个角色扮演游戏*和第四章中的*让我们建立一个侧面卷轴游戏*的`index.html`文件都包含 canvas 的以下 CSS 代码：

```js
.button {
  background-image: url(media/iphone-buttons.png);
  background-repeat: no-repeat;
  width: 192px;
  height: 32px;
  position: absolute;
  bottom: 0px;
}
-webkit-touch-callout: none;
-webkit-user-select: none;
-webkit-tap-highlight-color: rgba(0,0,0,0);
-webkit-text-size-adjust: none;#buttonLeft {
  position: absolute;
  top: 50%;
  left: 10%;
  width: 32px;
  background-position: -32px;
  height: 32px;
  visibility:hidden;
}
```

1.  首先，我们定义了完整的按钮面板。它的高度为 32 像素，宽度为 192 像素（六个按钮，每个 32 像素宽）。

1.  在这个按钮中，我们可以分别定义六个不同的部分。在这里，你可以看到左按钮的 CSS 代码。其他五个按钮使用完全相同的代码，除了它们的背景位置，因为这是它们在`iphone-buttons.png`图像上的位置。因此，例如，对于左按钮，位置是`-32`，对于右按钮，位置是`0`，对于上按钮，位置是`-64`，因为它是第三行。`webkit`命令是为了保持布局整洁，如预期的那样。如果没有提供这些命令，用户可能会意外地通过点击屏幕改变缩放或颜色。

1.  然而，我们只希望我们的按钮显示在移动设备上。因此，让我们在`index.html`文件中用一小段 JavaScript 代码来控制，如下面的代码片段所示：

```js
<script type="text/javascript">
  <!--//test if it is a mobile device-->
varisMobile= {
    Android: function() {
      return navigator.userAgent.match(/Android/i) ? true : false;
    },
    BlackBerry: function() {
      return navigator.userAgent.match(/BlackBerry/i) ? true : false;
    },
    iOS: function() {
      return navigator.userAgent.match(/iPhone|iPad|iPod/i) ? true : false;
    },
    Windows: function() {
      return navigator.userAgent.match(/IEMobile/i) ? true : false;
    },
    any: function() {
      return (isMobile.Android() || isMobile.BlackBerry() || isMobile.iOS() || isMobile.Windows());
    }
  };
  function mobileButtons(){
    <!-- show the mobile buttons -->
    if(isMobile.any()){
      document.getElementById('buttonLeft').style.visibility = 'visible';
      document.getElementById('buttonRight').style.visibility = 'visible';
      document.getElementById('buttonUp').style.visibility = 'visible';
      document.getElementById('buttonDown').style.visibility = 'visible';
      document.getElementById('buttonShoot').style.visibility = 'visible';
      document.getElementById('buttonJump').style.visibility = 'visible';
    }
  };
</script>
```

1.  在这个脚本的第一部分中，我们定义了本地变量`isMobile`。如果检测到移动设备，则设置为`true`，否则设置为`false`。在第二部分中，如果`isMobile`为`true`，则将 CSS 对象的可见性设置为`visible`。请记住，在`index.html`的 CSS 部分中创建它们时，它们的可见性被设置为`hidden`。

1.  在我们的`index.html`文件中，唯一剩下的事情就是将这些按钮作为`<div>`元素添加到我们的`canvas`元素旁边，如下面的代码所示：

```js
<body onLoad='mobileButtons()'>
  <div id="game">
    <canvas id="canvas"></canvas>
 <div class="button" id="buttonLeft"></div>
 <div class="button" id="buttonRight"></div>
 <div class="button" id="buttonUp"></div>
 <div class="button" id="buttonDown"></div>
 <div class="button" id="buttonShoot"></div>
 <div class="button" id="buttonJump"></div>
  </div>
</body>
```

`index.html`文件现在有按钮，只有在检测到移动设备时才会显示，但这还不足以使我们的游戏准备就绪。为此，我们需要调整我们的`main.js`脚本。

1.  打开`main.js`，并将以下代码添加到`game`实例的`init()`方法中：

```js
if(ig.ua.mobile){
  // controls are different on a mobile device
  ig.input.bindTouch( '#buttonLeft', 'Left' );
  ig.input.bindTouch( '#buttonRight', 'Right' );
  ig.input.bindTouch( '#buttonUp', 'Up' );
  ig.input.bindTouch( '#buttonDown', 'Down' );
  ig.input.bindTouch( '#buttonJump', 'changeWeapon' );
  ig.input.bindTouch( '#buttonShoot', 'attack' );
  //alert('control setup');
}else{
  //initiate background music
  var play_music = true;
  var music = ig.music;
  music.add("media/music/backgroundMusic.ogg");
  music.volume = 0.0;
  music.play();
}
```

1.  如果检测到移动设备，则虚拟按钮将绑定到游戏输入状态。因此，例如，`buttonLeft`元素将绑定到输入状态`Left`。

1.  `else`语句中的代码会打开背景音乐（如果有的话）。正如在第六章中所述，*音乐和音效*，一些移动设备不允许声音重叠。因此，对于移动设备，关闭背景音乐是明智的，这样它就不会与其他音效重叠。这可能不会永远是一个问题，但现在考虑这些声音问题是明智的。

1.  我们还需要调整我们的画布大小，以便它适合智能手机或 iPad 的屏幕。替换默认的画布调用：

```js
ig.main('#canvas', OpenScreen, 60, 320, 320,2);
```

使用以下代码替换默认的画布调用：

```js
if( ig.ua.iPad ) {
  ig.main('#canvas', MyGame, 60, 240, 160, 2);
}
else if( ig.ua.mobile ) {
  ig.main('#canvas', MyGame, 60, 160, 160, 2);
}
else {
  ig.main( '#canvas', OpenScreen, 60, 320, 320, 2 );
}
```

1.  所有这些只是使用不同的画布尺寸初始化游戏，以便它适合 iPad（或其他平板电脑）和智能手机等较小屏幕。此外，这里跳过了介绍屏幕；这是一个选择，你可以在移动设备上留下它。您还可以为更多设备调整画布大小。这里只显示了 iPad 和所有其他移动设备，但当然还可以进行更多的区分。

万岁！您的游戏现在已经准备好移动设备使用了！在将其上线之前不要忘记进行烘烤；移动互联网不像常规 Wi-Fi 那样快，因此使您的文件更小在这里绝对很重要。

接下来，我们将看看如何为**Chrome 网络商店**制作移动网络应用，但首先让我们快速回顾一下如何为移动浏览器准备我们的游戏。

总结前面的内容，结论如下：

+   如果我们希望玩家在移动设备上有良好的游戏体验，我们需要调整游戏界面以适应这一点。我们通过添加虚拟按钮来实现这一点。

+   虚拟按钮的视觉方面是使用 CSS 和`index.html`中的图像文件创建的。我们可以根据游戏是在移动设备上玩还是在其他设备上玩来使按钮可见或隐藏。

+   在我们游戏的`main`脚本中，我们需要将这些按钮绑定到游戏动作状态，以便获得与键盘相同的功能。

+   此外，我们可以更改游戏屏幕分辨率和大小，使其更适合玩家使用的设备。

# 将游戏转化为谷歌 Chrome 网络商店的网络应用

网络应用是在浏览器中运行的应用程序，而不是在移动设备的操作系统上运行。要在谷歌 Chrome 网络商店发布网络应用，您需要一个谷歌 Chrome 开发者帐户，这需要支付一次性费用 5 美元。您需要一个谷歌站长帐户来确认谷歌提供给您的链接的所有权。此外，为了不使事情变得更加困难，最好获得一个免费的 AppMobi 帐户。您可以在他们的网站上做到这一点：[`www.appmobi.com`](http://www.appmobi.com)。AppMobi 是一个非常有趣的初学者工具，有三个主要原因：

1.  他们简化了将游戏推送到多个不同的分发渠道的过程。

1.  他们对您的应用程序或游戏的前 10,000 个用户不收费，这样您可以先赚钱，然后再要求您分一杯羹；这的确是一个非常有吸引力的定价方案。

1.  ImpactJS XDK（跨环境开发工具包）通过创建人工视口来帮助将游戏适应不同的移动设备。它包含许多其他有用的功能，如模拟位置检测。

AppMobi 便于为以下平台构建游戏版本：iOS、Android、AppUp、亚马逊、Nook、Facebook、Chrome、Mozilla 和 hostMobi（他们自己的云主机服务）。

订阅后，您可以安装他们的 ImpactJS XDK 进行开发。安装 XDK 后，它将在 Chrome 浏览器中变得非常易于访问，并在您的地址栏旁边显示一个插件图标，如下面的屏幕截图所示：

![将游戏转化为谷歌 Chrome 网络商店的网络应用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_3.jpg)

您可以登录到 appHub：AppMobi 控制面板，以访问其所有服务。我们现在特别感兴趣的是构建一个谷歌 Chrome 游戏。以下是构建 Chrome 游戏的步骤：

1.  首次登录时，您需要通过单击以下截图中显示的按钮向您的控制中心添加一个新游戏：![将游戏转变为谷歌浏览器网络商店的网络应用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_4.jpg)

1.  为游戏命名并以压缩格式上传到服务器，如下截图所示：![将游戏转变为谷歌浏览器网络商店的网络应用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_5.jpg)

1.  您将看到 AppMobi 允许您为不同的分发渠道准备文件，如下截图所示：![将游戏转变为谷歌浏览器网络商店的网络应用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_6.jpg)

1.  在我们能够构建一个 Chrome `ready`文件之前，我们需要通过按下**PROMOTE**按钮将我们的文件推广到生产，如下截图所示：![将游戏转变为谷歌浏览器网络商店的网络应用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_7.jpg)

1.  我们想要为 Chrome 构建一个游戏，所以检查您仍然存在的问题。很可能您只需要为游戏添加一个图标。但是您需要在构建游戏之前执行此操作，如下截图所示：![将游戏转变为谷歌浏览器网络商店的网络应用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_8.jpg)

1.  如果一切顺利，您应该能够下载一个`production`文件，然后需要使用以下截图中显示的按钮将其上传到 Chrome 网络商店：![将游戏转变为谷歌浏览器网络商店的网络应用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_9.jpg)

1.  现在是时候将文件上传到 Chrome 网络商店了。但是在这样做之前，打开您刚从 AppMobi 网站下载的压缩文件夹，并确保 Chrome 图标的名称与 AppMobi 添加的`manifest.json`文件中所述的名称完全相同。这是一个已知的问题，Chrome 不会接受不一致的命名。

1.  如果您是第一次上传，您将收到一条消息，说您需要验证谷歌提供给您的域名所有权。为了做到这一点，您必须将谷歌允许您下载的带有标记的 HTML 文件插入到您首次上传到 AppMobi 的捆绑包中，并重新上传您的游戏到 AppMobi，这次在压缩的捆绑包中包含验证文件。在 AppMobi 中，使用**UPDATE QA**按钮上传新文件。之后不要忘记推广到生产。![将游戏转变为谷歌浏览器网络商店的网络应用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_10.jpg)

1.  在谷歌站长工具中，您需要添加谷歌提供的链接并进行验证，如下截图所示：![将游戏转变为谷歌浏览器网络商店的网络应用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_11.jpg)

1.  现在您可以重新上传到 Chrome 网络商店，并填写所有必要的元素。您需要添加游戏的详细描述、定价方案和截图，使用以下截图中显示的按钮：![将游戏转变为谷歌浏览器网络商店的网络应用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_12.jpg)

如果一切顺利，您将能够将您的游戏作为网络应用进行测试，并将其添加到您的谷歌 Chrome 中。如果出现问题，AppMobi 有大量关于其服务的文档和如何使用它们的信息。

现在我们有了一个网络应用，但是我们可以通过大致相同的过程来获得一个真正的应用程序。在本书中，我们将以 Android 为例。在这之前，让我们快速回顾一下。

总结前面的内容，结论如下：

+   网络应用是在浏览器中运行的应用程序，而不是直接在设备的操作系统上运行。谷歌浏览器在其谷歌浏览器网络商店中提供此类网络应用。在商店发布需要支付一次性 5 美元的订阅费。

+   AppMobi 提供了一种构建 Web 应用和应用的简单方法。注册是免费的，但一旦游戏取得一定的成功，就需要付费。

+   烘烤好的游戏需要被压缩并上传到 AppMobi 服务器。在这里，AppMobi 会对其进行适配，然后你可以重新下载并上传到 Chrome 开发者账户。

+   谷歌会提供一个链接，你需要重新上传到 AppMobi 并通过谷歌站长账户进行验证。

+   链接验证通过后，你可以重新上传游戏到 Web 商店，并填写游戏描述等详细信息。

+   在提交应用程序进行审核和发布到公众之前，你可以在浏览器中测试你的游戏。

# 将游戏推送到 Android 的谷歌应用商店

现在我们知道了如何构建 Web 应用，让我们在**谷歌应用商店**上构建一个真正的移动应用。我们将再次利用我们的 AppMobi 账户来完成这项工作。但是，此外，你还需要一个谷歌开发者账户，每年需支付 25 美元，用于在谷歌应用商店发布你的游戏。以下是将游戏推送到谷歌应用商店的步骤：

1.  使用上传到**AppMobi appHub**的`上传游戏`包或上传一个新的包。

1.  在**Android**选项卡下选择**构建**，并解决你仍然存在的任何问题。如果你成功构建了 Chrome 商店的 Web 应用程序，那么只剩下一个问题：设置谷歌云消息传递。为此，你需要一个**谷歌项目 ID**和一个**API 密钥**；你需要从你的开发者账户中获取这两者。

1.  在[`play.google.com/apps/publish/signup`](https://play.google.com/apps/publish/signup)注册开发者账户，或者如果你已经有账户就登录。

1.  转到你的**Google APIs**控制台并创建一个新项目。你可以从[`code.google.com/apis/console/`](https://code.google.com/apis/console/)选择你的项目 ID。

1.  在**服务**部分启用**Android 的谷歌云消息传递**，如下截图所示：![将游戏推送到 Android 的谷歌应用商店](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_13.jpg)

1.  在控制中心的**API 访问**部分选择**创建新的服务器密钥**。创建新服务器后，你也会收到 API 密钥。

1.  返回到 AppMobi appHub，在那里填写项目 ID 和 API 密钥。你现在已经设置好了推送消息。下面的截图显示了推送消息设置完成后的屏幕：![将游戏推送到 Android 的谷歌应用商店](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_14.jpg)

1.  你的应用现在应该准备好构建了。点击**立即构建**按钮，下载`apk`文件，如下截图所示：![将游戏推送到 Android 的谷歌应用商店](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_15.jpg)

1.  现在你需要做的就是将这个文件上传到你的开发者控制台。谷歌将要求你填写名称、描述，并添加一些截图。完成这些步骤后，你就可以开始了。

在将你的应用提交到应用商店进行审核之前，建议在多部移动设备上测试从 AppMobi 下载的`构建`文件是否流畅运行。你可以通过将文件上传到你自己的网站并用智能手机下载来完成测试。或者，你可以使用免费的云存储服务，如**Dropbox**，将文件从云端传输到你想要测试的任何设备上。

现在我们已经构建了应用和 Web 应用，我们将深入研究在**Facebook**上发布你的游戏的方法。在这之前，让我们快速回顾一下。

总结前面的内容，结论如下：

+   使用 AppMobi 构建应用与构建 Web 应用的过程几乎相同。但是，为了将你的游戏发布为应用，你需要一个谷歌开发者账户，每年需支付 25 美元。

+   如果你还没有将压缩的`游戏`文件上传到 AppMobi appHub，请先这样做。确保从 Google APIs 获得项目 ID 和 API 密钥。

+   构建您的`android`文件并将其上传到您的开发人员帐户，然后可以将其发送进行审查。但在这样做之前，请务必在几部 Android 移动设备上测试您的游戏。

# 在 Facebook 上提供您的游戏

AppMobi 可以用于构建 Facebook 应用程序，但 Facebook 还允许另一种选项来展示您的游戏。您需要一个 Facebook 开发人员帐户与您的 Facebook 帐户配套使用。目前没有订阅费。您可以转到以下链接获取您的 Facebook 开发人员帐户：

[`developers.facebook.com`](http://developers.facebook.com)

如果您已经在自己的网站上运行游戏，Facebook 允许您在您的网站上设置游戏的视口。

以下是使您的游戏在 Facebook 上可用的步骤：

1.  在您的帐户的应用程序部分，通过单击以下按钮创建一个新应用程序：![在 Facebook 上提供您的游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_16.jpg)

1.  填写**Facebook 应用**部分，如下面的屏幕截图所示。如果您的游戏也可以在移动设备上查看，还可以填写**移动网络**部分。确保**沙盒模式**打开，直到您彻底测试了所有内容。![在 Facebook 上提供您的游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_17.jpg)

1.  转到**应用详细信息**页面，在那里您需要填写有关您的游戏的一些基本信息：类别、描述和一些屏幕截图。一旦准备好，您可以通过单击以下按钮之一来预览您的游戏：![在 Facebook 上提供您的游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_18.jpg)

1.  尝试返回您自己的个人资料页面，您将在应用程序列表中找到您的游戏，如下面的屏幕截图所示。单击它以玩游戏并对您自己的 Facebook 游戏进行测试。![在 Facebook 上提供您的游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_19.jpg)

这不是将游戏发送到 Facebook 的唯一方法。您可以使用 AppMobi 制作一个真正的 Facebook 应用程序。但是，一旦您的游戏完成并存储在 Web 服务器的某个位置，这是一个非常快速的方法将其放在 Facebook 上。这种方法还有一个很大的优势：游戏仍然存储在您控制的服务器上，Facebook 仅提供一个视口。这意味着如果 Facebook 更改了某些内容，这对您的游戏的兼容性几乎没有影响，您不必在任何地方更改代码。

作为本章的最后一个主题，我们将快速查看 AppMobi 的直接画布实现。这是一个有趣的概念，因为它允许游戏运行速度比以往快得多。但是，首先让我们回顾一下。

总结前面的内容，结论如下：

+   有几种方法可以将您的游戏带到 Facebook。由于我们已经使用 AppMobi 构建应用程序，我们将研究视口解决方案。

+   您需要将游戏放在服务器上并拥有免费的 Facebook 开发人员帐户。

+   转到**应用**部分，并创建一个具有普通画布和/或移动 URL 的新应用程序。还填写所有应用程序详细信息。

+   在发布之前彻底测试您的游戏。您可以在您自己的个人 Facebook 页面的应用程序之间找到您的游戏。

# 使用 AppMobi 进行直接画布游戏加速

HTML5 游戏很棒，因为 HTML 和 JavaScript 可以被任何浏览器解释，并且转换为应用程序相当简单。易于“部署”是一个很大的优势，但它也带来了一个相当大的劣势。画布元素为了实际渲染游戏所需的资源可能是惊人的，一旦您想要同时使用许多实体，系统延迟很容易就会出现。在游戏体验中，很少有比这更糟糕的事情，这就像看幻灯片一样。但是，有一些技巧可以改善这一点，比如在第七章 *图形*中建议的预渲染图形。

如果你想利用直接画布提供的性能提升，实现起来相当简单。但是，首先你需要为 AppMobi ImpactJS XDK 准备好你的代码。以下是实现直接画布加速的步骤：

1.  转到 Chrome Web Store 并安装 Impact XDK 扩展。

1.  在 XDK 中，登录你的 AppMobi 账户并添加一个新项目。在 XAMPP（或 WAMP）库中选择你游戏的`root`文件夹。以下截图显示了开始新项目的按钮：![使用 AppMobi 实现直接画布游戏加速](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_20.jpg)

1.  XDK 会警告你尚未在游戏中包含 AppMobi 库，因此你将无法使用 AppMobi 命令。按照弹出窗口建议的方式，将以下代码复制到剪贴板中：![使用 AppMobi 实现直接画布游戏加速](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_21.jpg)

1.  打开你的`index.html`文件，并将脚本粘贴到文档的`head`部分。现在你的游戏已经准备好在 Impact XDK 中查看，当需要时你可以添加 AppMobi 命令，如下面的代码片段所示：

```js
<!-- the line below is required for access to the appMobi JS library -->
<script type="text/javascript" charset="utf-8" src="img/appmobi.js"></script>
<script type="text/javascript" language="javascript">
  // This event handler is fired once the AppMobilibraries are ready
  function onDeviceReady() {
    //use AppMobi viewport to handle device resolution differences if you want
    //AppMobi.display.useViewport(768,1024);
    //hide splash screen now that our app is ready to run
    AppMobi.device.hideSplashScreen();
  }
  //initial event handler to detect when appMobi is ready to roll
  document.addEventListener("appMobi.device.ready",onDeviceReady,false);
</script>
```

现在我们的游戏在 XDK 中运行。然而，我们还没有直接画布加速。

1.  在你游戏的`root`文件夹中创建一个名为`index.js`的新脚本，并添加以下代码：

```js
AppMobi.context.include( 'lib/impact/impact.js' );
AppMobi.context.include( 'lib/game/main.js' );
```

1.  打开`index.html`并将`AppMobi`命令添加到`onDeviceReady()`事件监听器中。以下代码将加载`index.js`脚本：

```js
functiononDeviceReady() {
  AppMobi.device.hideSplashScreen();
 AppMobi.canvas.load("index.js");
}
```

1.  删除包括你的游戏和 impact 引擎脚本的以下`script`标签：

```js
<script type="text/javascript" src="img/impact.js"></script>
<script type="text/javascript" src="img/main.js"></script>
```

1.  删除以下的`canvas`元素：

```js
<body>
 <canvas id="canvas"></canvas>
</body>
```

1.  打开`main.js`脚本，并将以下内容添加到所需脚本的列表中：

```js
'plugins.dc.dc'
```

1.  如果你的代码中有画布样式的引用，请从中删除。例如：`ig.system.canvas.style.width = '320px'`。

1.  最后，删除你可能已经实现的触摸事件绑定，并用 AppMobi 版本替换它们。`<div>`元素可以留在`index.html`文件中，但你需要附加其他事件。例如，对于`shoot`按钮`<div>`元素：

```js
onTouchStart="AppMobi.canvas.execute('ig.input.actions[\'shoot\']=true;ig.input.presses[\'shoot\']=true;');" onTouchEnd="AppMobi.canvas.execute('ig.input.delayedKeyup.push( \'shoot\' )');"
```

恭喜！你现在已经成功实现了直接画布加速！当在 Impact XDK 中玩游戏时，你可能会注意到画布元素的轮廓已经消失，如下面的截图所示：

![使用 AppMobi 实现直接画布游戏加速](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_8_22.jpg)

# 总结

本章的目标是提供在多种方式发布游戏时所需的技术准备。首先，我们看了一下烘焙游戏代码的过程，这可以缩短加载时间并使源代码不那么易读。烘焙应该在分发游戏之前进行。然后我们深入研究了通过实现触摸控制来适应移动浏览器的游戏。将游戏转换为 Web 应用程序或 Android 应用程序是通过 AppMobi 完成的。在发布到 Facebook 时，你有几个选项，我们深入研究了其中一个。在这个解决方案中，你自己的网站充当实际平台，而 Facebook 仅提供一个视口。在移动设备上，运行游戏时处理能力和内存使用可能是真正的问题。因此，我们看了 AppMobi 的直接画布实现。通过摆脱普通的 HTML 画布元素，可以消除大量的开销处理，大大减少必要的资源。

在下一章中，我们将看看作为 HTML5 游戏开发者的赚钱选择，希望能把爱好变成工作。


# 第九章：用你的游戏赚钱

在本章中，我们将快速了解 HTML5 游戏开发赚钱的选项。制作游戏可以纯粹是一种爱好，也可以是一种职业。然而，后者要求你制作一些非常独特和成功的游戏，因为竞争非常激烈。因此，提供一个独特的游戏主张，并得到健康的营销支持，似乎是大多数成功游戏开发者的选择。在本章中，我们将涵盖：

+   进入游戏开发时你有的一些战略选择

+   在安卓和苹果的应用市场赚钱

+   游戏内广告选项及其在 HTML5 游戏中的应用

+   MarketJS 作为向出版商出售发行权的途径

# 你的游戏开发策略

如果你想制作一款游戏来赚钱，那么在开始制作之前，有几件事情是必须考虑的。你需要问自己的第一个问题可能是：我要为谁制作游戏？你是针对所有能玩游戏的人，还是想要针对非常特定的人群并满足他们的游戏需求？这就是广泛和小众定位之间的区别。大多数塔防游戏都是非常广泛的目标游戏，你需要建造具有不同属性的塔来抵御敌军。例如《俄罗斯方块》、《宝石迷阵》、《扫雷》和大多数轻盈的益智游戏。《愤怒的小鸟》是另一个例子，它因其简单性、可爱的图形和大量巧妙的营销而受到广泛受众的欢迎。

总的来说，休闲游戏似乎吸引大众的原因有以下几个因素：

+   简单为主：大多数玩家在短短几分钟内就能适应游戏。

+   几乎没有知识先决条件：你不需要已经了解一些背景故事或在这些类型的游戏中有经验。

+   即使投入的练习时间较少，休闲玩家也往往表现不错。即使你一开始就表现不错，你仍然可以变得更好。一个你无法通过重玩变得更好的游戏不会长久。值得注意的例外是像轮盘赌和老虎机这样的机会游戏，它们确实会上瘾；但这是出于其他原因，比如赢钱的机会。

建造休闲游戏的主要优势在于几乎每个人都是你游戏的潜在用户。因此，可实现的成功可能是巨大的。《魔兽世界》是一款游戏，多年来已经从相当激烈和小众的游戏转变为更加休闲的游戏。他们之所以这样做，是因为他们已经吸引了大多数普通玩家，并决定说服大众，即使你一般不怎么玩游戏，也可以玩《魔兽世界》。试图取悦所有人的缺点是竞争的数量。在众多游戏中脱颖而出是非常困难的。特别是如果你没有一个强大的营销机器来支持它。

一个很好的例子是任何一款根据电影制作的游戏。《星际迷航》、《星球大战》、《指环王》等游戏，大多针对已经看过并喜欢这些电影的人。小众游戏也可能是小众，因为它们只针对特定的玩家群体。例如，喜欢玩第一人称射击游戏（FPS）的人，每天都这样做。实质上，小众游戏具有以下特点（请注意，它们与休闲或广泛定位的游戏相对）：

+   陡峭的学习曲线：掌握需要许多小时的专注游戏。

+   需要一些游戏知识或经验。例如《星球边际 2》这样的在线射击游戏，你至少需要一些以前的射击游戏经验，因为你将与知道自己在做什么的人对抗。

+   你玩游戏的次数越多，你获得的有用奖励就越多。经常玩游戏通常会获得使你在游戏中更强大的物品，从而加强了你通过更多游戏而变得更好的事实。

《星际争霸》是暴雪在 1998 年发布的一款游戏，即使有了续作《星际争霸 2》，它仍然在今天的比赛中被玩家们玩耍。原版《星际争霸》等游戏完全可以在 HTML5 中构建，并在浏览器或智能手机上运行。当《星际争霸》发布时，平均台式电脑的性能远不及今天许多智能手机。从技术上讲，道路是开放的；然而复制相同的成功水平又是另一回事。

瞄准游戏玩家群体的优势在于你可以在他们的生活中占据独特的位置。也许你的目标群体并不多，但由于游戏是专门为他们打造的，因此更容易吸引并保持他们的注意。此外，这并不意味着因为你有一个明确的目标，玩家就不能从意想不到的角落进入。你从未想过会玩你的游戏的人仍然可能喜欢你所做的事情。正是因为这个原因，了解你的玩家是如此重要，这也是像 Playtomic 这样的工具存在的原因。

利基营销的劣势是显而易见的：你的游戏很不可能超越一定的范围；它可能永远不会成为世界上最受欢迎的游戏之一。

你将要开发的游戏类型是一个选择，你在每款游戏中投入的细节数量是另一个选择。你可以尽可能多地努力去打造一款游戏。实质上，一款游戏永远不会完成。游戏总是可以有额外的关卡、彩蛋或其他精彩的细节。在规划游戏时，你必须决定你将使用霰弹枪还是狙击手的开发策略。

在霰弹枪策略中，你会快速开发和发布游戏。每款游戏仍然有一个独特的元素，应该使其与其他游戏有所区别：UGP（独特游戏命题）。但是在霰弹枪策略下发布的游戏并不提供很多细节；它们并不完善。

采用霰弹枪策略的优势有很多：

+   低开发成本；因此每款游戏代表着低风险

+   快速上市允许利用世界事件作为游戏背景

+   你可以同时在市场上推出多款游戏，但通常你只需要一款成功的游戏来支付其他游戏的开支

+   短小的游戏可以免费提供给公众，但通过出售附加内容（如关卡）来实现盈利

然而，当你采用这种策略时，并不全是美好的。有几个原因你不会选择霰弹枪策略：

+   一个感觉不完整的游戏成功的机会比一个完美的游戏要小。

+   将游戏投放市场不仅测试了某个概念是否可行，还使其暴露于竞争对手，他们现在可以开始制作副本。当然，你有先发优势，但并不像可能的那么大。

+   你必须始终小心，不要在市场上乱丢垃圾，否则你可能会毁了自己作为开发者的名声。

然而，不要混淆。霰弹枪策略并不是建造平庸游戏的借口。你发布的每款游戏都应该有独特的特色——没有其他游戏有的东西。如果一个游戏没有新的特色，为什么有人会选择它而不是其他所有游戏呢？

当然，还有狙击策略，它涉及构建一个体面且经过深思熟虑的游戏，并在市场上以最大的关怀和支持发布。这是苹果等分发商敦促开发者做的事情，也是有充分理由的——你不希望你的应用商店里充斥着糟糕的游戏，对吧？一些其他游戏分发商，比如 Steam，在允许分发的游戏方面更加挑剔，使得散弹策略几乎不可能。但这也是最成功的游戏开发者使用的策略。看看 Rockstar（GTA 系列的开发者）、Besthesda（上古卷轴系列的开发者）、Bioware（质量效应系列的开发者）、暴雪（魔兽世界系列的开发者）等开发者。这些都不是小角色，但他们在市场上的游戏并不多。开发高质量游戏并希望它们能够成功显然是有风险的。为了开发一个真正了不起的游戏，你还需要时间和金钱。如果你的游戏销售不佳，这对你或你的公司来说可能是一个真正的问题。即使对于 HTML5 游戏来说，情况也可能如此，特别是因为设备和浏览器变得越来越强大。当运行游戏的设备变得更强大时，游戏本身通常会变得更加复杂，开发时间也会更长。

我们已经看了进入游戏开发业务时需要做出的两个重要选择。现在让我们来看一下允许你通过游戏赚钱的分发渠道，但在此之前让我们总结一下我们刚刚讨论过的主题：

+   在开始开发游戏之前，决定你想要针对的目标群体非常重要。

+   广泛的目标实际上根本就不是目标。它是关于让尽可能多的人能够接触和喜欢游戏。

+   利基定位是深入研究和关注特定群体，并开发适合他们特定游戏需求的游戏。

+   在开发和发布游戏时，有两种主要策略：散弹和狙击。

+   在散弹策略中，你会快速发布游戏。每个游戏仍然具有其他游戏所不具备的独特元素，但它们不像可能那样精心制作和打磨。

+   采用狙击策略，你只开发少量游戏，但每个游戏在发布时已经完美，并且只需要在发布补丁时进行轻微的打磨。

# 通过游戏应用赚钱

如果你将你的游戏制作成应用程序，你可以选择多个分发渠道，比如 Firefox 市场、IntelAppUp 中心、Windows Phone 商店、亚马逊应用商店、SlideMe、Mobango、Getjar 和苹果 Appsfire。但目前市场上最受欢迎的玩家是 Google Play 和 iOS 应用商店。iOS 应用商店不应与 Mac 应用商店混淆。iPad 和 Mac 有两个不同的操作系统，iOS 和 Mac OS，因此它们有不同的商店。游戏可以在 iOS 商店和 Mac 商店发布。还可能会有一些混淆，例如 Google Play 和 Chrome Web 商店。Google Play 包含所有适用于搭载谷歌安卓操作系统的智能手机的应用程序。Chrome Web 商店允许你向 Google Chrome 浏览器添加应用程序。因此有很多分发渠道可供选择，我们将简要介绍一下 Google Play、iOS 应用商店和 Chrome Web 商店。

## 谷歌 Play

谷歌 Play 是安卓的默认应用商店，也是 iOS 应用商店最大的竞争对手。

如果你想成为安卓应用开发者，需要支付 25 美元的费用，并且必须阅读开发者分发协议。

作为进入费和签署协议的回报，他们允许您使用他们的虚拟货架并享有所有的好处。您可以随意设置价格，但是对于您出售的每款游戏，Google 将收取约 30％的费用。可能会进行一些地理价格歧视。因此，您可以在比利时将价格设定为 1 欧元，而在德国收取 2 欧元。您可以随时更改价格；但是，如果您免费发布游戏，就无法回头了。之后，该应用的唯一变现方式是允许游戏内广告、出售附加内容或创建可以用真钱购买的游戏内货币。

引入用真钱购买的游戏内货币可能是一种非常吸引人的格式。这种变现方案的一个非常成功的例子可以在《蓝精灵》游戏中找到。在这个游戏中，您可以建立自己的蓝精灵村庄，包括大蓝精灵、蓝精灵和大量的蘑菇。您种植更多庄稼并建造新房子，您的城市会变得更大，但这是一个缓慢的过程。为了加快速度，您可以用真钱购买特殊的浆果，从而可以建造独特的蘑菇和其他东西。这种变现方案变得非常受欢迎，正如在《英雄联盟》、《星球边境 2》、《坦克世界》等游戏中所显示的那样。对于 Google Play 应用，这种应用内支付系统得到了 Android 的 Google Checkout 的支持。

此外，Google 允许您访问有关游戏的一些基本统计数据，例如玩家数量和他们玩游戏的设备，如下图所示：

![Google Play](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_9_2.jpg)

这样的信息可以让您重新设计游戏以提高成功率。例如，您可以注意到某个设备的独立用户数量并不多，尽管它是非常受欢迎的设备，被许多人购买。如果是这种情况，也许您的游戏在这种特定的智能手机或平板电脑上看起来不太好，您应该对其进行优化。

所有应用的最大竞争对手和发起者都是 iOS 应用商店，所以让我们来看看这个。

## iOS 应用商店

iOS 应用商店是第一个这样的应用商店，在撰写本书时，它仍然拥有最大的收入。

要在 iOS 应用商店发布应用，您需要订阅 iOS 开发者计划，每年费用为 99 美元，几乎是 Google Play 的四倍。实际上，它们提供的东西与 Google Play 几乎相同；正如您在这个简短的列表中所看到的：

+   您可以自行定价，并获得销售收入的 70％

+   您可以每月收到无需信用卡、托管或营销费用的付款

+   有支持和充分的文档可供您开始

更重要的是，以下是 Google Play 和 iOS 应用商店之间的区别：

+   如前所述，注册 Google Play 更便宜。

+   苹果的筛选过程似乎比 Google Play 更严格，这导致了更长的时间才能进入市场，甚至有更高的可能性根本无法进入市场。

+   Google Play 包含退款选项，允许购买您的应用的人在 24 小时内卸载应用或游戏后获得退款。

+   如果您希望您的游戏能够利用一些 Android 核心功能，这是可能的，因为该平台是开源的。另一方面，苹果对其 iOS 平台非常保护，并且不允许应用程序具有相同级别的灵活性。这个元素对于游戏来说可能还不那么重要，但对于那些确实希望利用这种自由的非常创新的游戏来说可能很重要。

+   iOS 覆盖的人数比 Android 多，尽管当前趋势表明这种情况可能在不久的将来会发生变化。

+   购买苹果设备的人和使用安卓系统智能手机或平板电脑的用户之间似乎存在显著差异。苹果粉丝对在应用上花钱的门槛似乎比安卓用户低。总的来说，iPad 和 iPhone 比其他平板电脑和智能手机更昂贵，吸引了那些对设备花更多钱没有问题的人。这种目标群体的差异似乎让安卓游戏开发者更难从他们的游戏中赚钱。

### 提示

如果你的游戏在 Safari 浏览器上运行，并不意味着它已经准备好被 iOS 应用商店接受。将你的游戏转换为本地应用需要一些额外的准备。同样的情况也适用于 Chrome 浏览器和 Google Play 商店。从浏览器游戏转换为应用可以使用 AppMobi，就像在第八章中展示的那样，*调整你的 HTML5 游戏到分销渠道*。

在这里我们将讨论的最后一个销售应用的选择是 Chrome 网络商店。

## Chrome 网络商店

Chrome 网络商店不同于 Google Play 和 iOS 应用商店，它提供的是专门为 Chrome 浏览器而不是移动设备的应用。

Chrome 商店提供网络应用。网络应用就像你在 PC 上安装的应用程序，只不过网络应用安装在你的浏览器中，大多数是使用 HTML、CSS 和 JavaScript 编写的，就像我们的 ImpactJS 游戏一样。关于 Chrome 商店值得注意的第一件事是发布应用的一次性 5 美元入场费。如果这本身还不够好，那么销售应用的交易费仅为 5％。这与 Google Play 和 iOS 应用商店有着显著的不同。如果你已经为自己的网站开发了一款游戏，并将其打包为安卓和/或苹果的应用，你也可以在 Chrome 网络商店上发布。将你的 ImpactJS 游戏转换为 Chrome 商店的网络应用可以使用 AppMobi，但 Google 本身提供了如何手动操作的详细文档。

网络应用的最大好处之一是简化了权限流程。假设你的网络应用需要用户的位置才能运行。而 iPad 应用每次需要位置数据时都会请求权限，网络应用只在安装时请求一次。

此外，它提供与 Google Play 相同的功能和支付方式。例如，还有一个包括免费试用版本的选项，也就是所谓的免费增值。免费增值模式是指允许免费下载演示版本，并提供升级到完整版本的选项。《蓝精灵》游戏也使用了免费增值模式，尽管有所不同。整个游戏是免费的，但玩家可以选择用真钱购买一些原本需要花费大量时间才能获得的东西。在这种免费增值模式中，你为方便和独特物品付费。例如，在《星际争霸 2》中，获得某个狙击步枪可能需要你花费几天或 10 美元，这取决于你选择如何玩免费增值游戏。

如果你计划为安卓发布 ImpactJS 游戏，那么在 Chrome 网络商店发布也是毫无理由不这样做的。

总之，让我们快速回顾一下：

+   iOS 应用商店是唯一的应用商店的时代早已一去不复返；现在有许多可供选择的应用商店，包括 Firefox Marketplace、Intel AppUp Center、Windows Phone Store、Amazon Appstore、SlideMe、Mobango、Getjar、Appsfire、Google Play 等。

+   目前最大的应用商店是 Google Play 和 iOS 应用商店。它们在几个方面有很大的不同，其中最重要的是：

+   订阅费

+   筛选流程

+   吸引的受众类型

+   Chrome 网络商店销售的是像普通应用一样的网络应用，但只能在 Chrome 浏览器中使用。

+   Chrome 网络商店便宜且易于订阅。你一定要试试在这个平台上发布你的游戏。

# 游戏内广告

游戏内广告是另一种赚钱的方式。游戏内广告是一个不断增长的市场，目前已经被主要公司使用；巴拉克·奥巴马在他 2008 年和 2012 年的竞选中也使用了游戏内广告，如下游戏内截图所示：

![游戏内广告](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_9_5.jpg)

有一种趋势是更加动态的游戏内广告。游戏制造商确保游戏中有广告空间，但实际的广告内容是后来决定的。根据对你的了解，这些广告可以随后变化，变得与你作为玩家和现实消费者相关。

当刚开始制作游戏时，游戏内广告并不那么引人注目。大多数知名的在线游戏内广告商甚至不希望他们的广告出现在初创游戏中。

Google AdSense 的要求如下：

+   **游戏玩法**：每天至少 500,000 次

+   **游戏类型**：仅限基于 Web 的 Flash

+   **集成**：必须具备 SDK 集成的技术能力

+   **流量来源**：80%的流量必须来自美国和英国

+   **内容**：适合家庭和面向 13 岁及以上的用户

+   **分发**：必须能够报告嵌入目的地并控制游戏的分发位置

另一家大竞争对手 Ad4Game 的要求也不轻松：

+   至少每天有 10,000 个独立访客

+   不接受子域和博客

+   Alexa 排名应该低于 400,000

+   不允许成人/暴力/种族主义内容

如果你刚开始，这些先决条件并不是好消息。不仅因为你需要如此多的玩家才能开始广告，而且因为目前所有的支持都是针对 Flash 游戏。HTML5 游戏目前还没有得到充分支持，尽管这可能会改变。

幸运的是，有一些公司允许你开始使用广告，即使你每天没有 10,000 个访问者。Tictacti 就是其中之一。

再次强调，几乎所有的支持都是针对 Flash 游戏的，但他们确实为 HTML5 游戏提供了一个选项：**预滚动**。预滚动简单地意味着在你开始游戏之前会出现一个带有广告的屏幕。预滚动广告的集成非常简单，不需要对游戏进行更改，只需要对你的`index.html`文件进行更改，就像 Tictacti 的以下示例一样：

```js
//You can use publisherId 3140 and tagTypedemoAPI for testing purposes however the ads will not be credit to you.
<html>
<head>
  <title>Simple Ad</title>
</head>
<body>
<script type="text/javascript"src="img/t3widgets.js"></script><script type="text/javascript">
  var publisherId = "3140";var tagType = "jsGameAPI";var agencyUniqueId= "0";var playerWidth = "600";//The Game widthvar playerHeight = "400";//The Game heightvar t3cfg = {wrapperUrl: 'engine/game/3170/tttGameWrapper.swf',
config: { enableDM: false, tttPreloader: false, bgcolor: "#000000", engineConnectorType: 7 , externalId:agencyUniqueId},
    onClose:function(){document.location="http://www.tictacti.com";}
    //Called after the ad is closed. In the Demo after 30 seconds.};
  TicTacTi.renderWidget(publisherId, tagType, playerWidth ,playerHeight , t3cfg);
</script>
</body>
</html>
```

在将其添加到游戏的`index.html`文件时，填写你自己的发布者 ID，基本上就可以开始了。

Tictacti 类似于 Google Analytics，它还为你提供了一些关于游戏网站上广告的相关信息，如下图所示：

![游戏内广告](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_9_7.jpg)

然而，要小心，预滚动广告是最具侵入性和恼人的广告之一。从技术上讲，它甚至不算是游戏内广告，因为它是在你玩游戏之前运行的。如果你的游戏还没有建立足够的声誉，无法说服玩家忍受广告才能开始游戏，就不要选择这个选项。给你的游戏一些时间来建立声誉，然后再让玩家忍受这些。

最后一个选择是通过 MarketJS 出售你的实际分发权。但首先让我们简要回顾一下游戏内广告：

+   游戏内广告是一个不断增长的市场。甚至巴拉克·奥巴马也利用游戏内广告牌来支持他的竞选活动。

+   有一种趋势是更加动态的游戏内广告——利用你的位置和人口统计信息来调整游戏中的广告。

+   目前，即使是最容易接触到的在线游戏广告公司也专注于 Flash 游戏，并要求有很多独立访问者才能允许你展示他们的广告。Tictacti 是一个值得注意的例外，因为它的先决条件低，实施简单；尽管广告目前仅限于预滚动广告。

+   始终要先为你的游戏建立良好的声誉，然后再允许广告。

# 使用 MarketJS 出售分发权

我们在本章中将要调查的最后一个选项是出售你的游戏分发权。你仍然可以通过将游戏发布到所有应用商店和你自己的网站上赚钱，但要被注意到变得越来越困难。只有当人们知道游戏存在时，质量才能获胜，因此制作一款好游戏有时是不够的——你需要营销。如果你是一个有很好的游戏创意和技能的初学者游戏开发者，那很好，但营销可能不是你的菜。这就是 MarketJS 发挥作用的地方。

MarketJS 充当游戏开发者和游戏出版商之间的中介。

一旦你有了游戏，程序就很简单：

1.  你可以在他们的网站[`www.marketjs.com`](http://www.marketjs.com)上注册。

1.  将游戏上传到你自己的网站或直接上传到 MarketJS 服务器。

1.  发布你的游戏供出版商查看。你可以设置一些选项，比如最适合你的价格和合同类型。你有五个合同选项：

+   **完整分发合同**：将你的游戏所有的分发权出售。

+   **独家分发合作伙伴合同**：在这里，你限制自己与一个分销商合作，但仍保留游戏的权利。

+   **非独家合同**：在这里，任何分销商都可以购买你游戏的使用权，但只要你愿意，你可以继续出售权利。

+   **收入分成**：在这里，你可以协商如何分配游戏产生的收入。

+   **定制合同**：这基本上可以有任何条款。如果你还不确定你想从你的游戏中得到什么，你可以选择这个选项。在填写你的合同偏好的网页部分如下截图所示：

![使用 MarketJS 出售分发权](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_9_9.jpg)

发布演示后，就是等待出版商发现它，被它的壮丽所震撼，并提出与你合作的要约。

MarketJS 对游戏领域的重大贡献在于让游戏开发者专注于开发游戏。其他人负责营销方面，这是完全不同的一回事。

MarketJS 还提供了一些有趣的统计数据，比如他们网站上游戏的平均价格，如下图所示。这让你对是否应该把游戏开发作为一种生活方式或者继续把它作为一种爱好有了一些见解。

![使用 MarketJS 出售分发权](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_9_10.jpg)

根据 MarketJS，非独家权利的价格平均在 500 到 1000 美元之间，而售出游戏的独家权利价格在 1500 到 2000 美元之间。如果你能在这个价格范围内制作一款体面的游戏，那么你已经准备好了：

+   MarketJS 是一家将游戏分销商和开发者联系在一起的公司。他们专注于 HTML5 游戏，所以如果你是一名初创的 ImpactJS 游戏开发者，他们是一个很好的选择。

+   他们不需要订阅费，并且有一个简单的流程将你的游戏变成一个带有价格标签的展示品。

# 总结

在本章中，我们已经看了一些重要的元素，考虑了你的游戏开发策略。你想采取散弹枪策略，在短时间内开发大量游戏吗？还是你会使用狙击手策略，只开发一些精心制作的游戏？你还需要决定你希望吸引的受众群体。你可以选择制作一款受到所有人喜爱的游戏，但竞争激烈。

在应用商店赚钱是可能的，但对于 Android 和 Apple 来说，有注册费。如果你决定开发应用程序，不妨试试 Chrome 网络应用商店（它运行网络应用）。

游戏内广告是资助你的努力的另一种方式，尽管大多数提供在线游戏服务的公司对此有很高的先决条件，并且更多地支持 Flash 游戏而不是更新的 HTML5 游戏。

最有前途的变现模式之一是免费模式。玩家可以自由玩游戏，但他们需要为额外的内容付费。这是一个容易被接受的模式，因为对于不愿意花钱的人来说，游戏基本上是免费的，而且也没有烦人的广告。

游戏内广告和免费模式的组合也是可能的：被广告打扰的人支付费用，作为回报，他们将不再受到打扰。

最后一个选择是通过与 MarketJS 合作出售你的发行权，将营销方面留给其他人。他们专注于 HTML5 游戏，这个选择对于初学者游戏开发者来说特别有用，因为他们在营销游戏方面可能会遇到困难。

我们现在已经到达了书的结尾，涵盖了大量的信息 - 从设置服务器的基础知识，到开发 ImpactJS 游戏，再到自己创作的分发。感谢你阅读了所有这些。

我希望能让整个过程更容易理解，并为你开始创作自己的游戏甚至可能靠此谋生提供最后的推动。有时，开发游戏可能会令人沮丧，因为魔鬼常常隐藏在细节中。你可能会发现自己经常咒骂屏幕，但请记住这不是电脑的错，只要有足够的决心，你总能找到解决方案。如果你有时感到迷茫，ImpactJS 网站有一个充满了非常乐于助人的人的论坛，我非常鼓励你利用它，在那里分享你的想法、问题和想法。当你关闭这本书，开始制作你的游戏时，不要忘记制定计划并以非常有条理的方式工作将是成功的关键因素，并可能避免许多不眠之夜。逐步进行变更和改进，并始终检查一切是否仍然按预期运行是正确的方式，可以交付一个完美运行的游戏。但是，尽管有组织和有条理的思维所带来的所有好处，还有另一个最重要的东西：你的想象力。

要有原创性，不要受到已有内容的限制，你无疑会创造出一款让数百万人喜欢的游戏，甚至可能经得起时间的考验。
