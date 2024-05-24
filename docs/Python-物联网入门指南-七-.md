# Python 物联网入门指南（七）

> 原文：[`zh.annas-archive.org/md5/4fe4273add75ed738e70f3d05e428b06`](https://zh.annas-archive.org/md5/4fe4273add75ed738e70f3d05e428b06)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二十四章：基本开关

到目前为止一定是一段史诗般的旅程！回想一下你开始阅读这本书的时候，你是否曾想象过事情会变得如此简单？值得注意的是，一切都是从非常简单的开始，然后慢慢地，随着对更复杂系统的需求，技术的复杂性也增加了。回到个人计算并不是真正的事情的时候。它只在商业中使用，像 IBM 这样的公司只为商业客户提供服务。那时，想要个人计算机的人只有一个选择。他们需要从头开始建造，老实说，很多人过去都这样做。至少从我的角度来看，这真的并不难。但是，与那个时代相比，想想它们现在变成了什么样子。曾经想过在家里建造一台计算机吗？我说的是设计一切，而不仅仅是组装 CPU。这并不容易。

我在这里想告诉你的是，曾经有一段时间，计算机是稀有的；它们并不常见，功能也非常有限。然而，随着时间的推移和像史蒂夫·乔布斯、比尔·盖茨、休利特和帕卡德这样的人的智慧，计算机变得更加用户友好，更容易获得，并成为一种令人向往的商品。想象一下同样的情况发生在机器人身上。它们很昂贵；对于大多数人来说，它们并没有太多用处，而且在公共场所也很少见。但是，正如你所学到的，为我们个人使用构建机器人并不是很难，再加上一些调整和你这样有创造力的头脑，事情可以朝着完全不同的方向发展。你可能会因为你的愿景而受到嘲笑。但请记住，每个发明家在某个时候都被称为疯子。所以下次有人称你为疯子时，你可以非常确定你正在进步！

嗯，我非常确定，如果你是一个机器人爱好者，那么你一定看过电影《钢铁侠》。如果你还没有看过，那就停下来阅读这本书，去打开 Netflix 看看那部电影。

有一次我看了那部电影，我想要制作两件东西：一件是钢铁侠的战衣，另一件是他的个人助手贾维斯，他照顾他的一切需求。虽然战衣似乎是我可能需要一段时间来研究的东西，但到那时，你可以继续为自己建立个人助手。

想象一下你的家自己做事情。那会多酷啊？它知道你喜欢什么，你什么时候醒来，你什么时候回家，基于此，它会自动为你做事情。最重要的是，它不会是你从货架上购买的东西，而是你亲手制作的。

在你做任何这些之前，我必须告诉你，你将处理高电压和相当大的电流。电力不是闹着玩的，你必须随时小心并佩戴所有安全设备。如果你不确定，那么最好找一个电工来帮助你。在触摸或打开任何电气板之前，确保你穿着不导电的鞋子；还要检查螺丝刀、钳子、鼻钳、剪刀和其他工具是否绝缘良好且处于良好状态。戴手套是个好主意，增加安全性。如果你未满 18 岁，那么你必须有一个成年人随时帮助你。

既然说到这里，让我们开始看看我们有什么。

# 让贾维斯叫醒你

现在，这个非常有趣，正如大家所知，我们的人体是按照一定的方式编程的。因此，我们对不同的刺激作出非常熟悉的反应。比如当天黑了，我们的大脑会产生触发睡眠的激素。一旦阳光照到我们的眼睛，我们就会醒来。好吧，至少应该是这样！最近，我们的生活方式发生了巨大变化，开始违背这种周期。这就是为什么我们看到越来越多的失眠病例。被闹钟吵醒绝对不是自然的。因此，即使它的铃声是您最喜欢的歌曲，您早上听到闹钟也不会开心。我们的睡眠周期应该与阳光同步，但现在几乎没有人会通过这种方式醒来。因此，在本章中，让我们首先制作一个智能闹钟，模拟我们醒来的自然方式。

# 使用继电器和 PIR 传感器

由于我们正在处理高电压和更高电流，我们将使用继电器。为此，请按以下方式连接电线：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/7f4fd337-c5a2-4a66-93c5-8e0155e8e213.png)

连接完成后，上传以下代码，让我们看看会发生什么：

```py
import RPi.GPIO as GPIO import time LIGHT = 23 GPIO.setmode(GPIO.BCM) GPIO.setwarnings(False) GPIO.setup(LIGHT,GPIO.OUT) import datetime H = datetime.datetime.now().strftime('%H') M = datetime.datetime.now().strftime('%M') 
 while True: if H = '06'and M < 20 : GPIO.output(LIGHT,GPIO.HIGH) else: GPIO.output(LIGHT,GPIO.LOW)
```

好的，这是一个非常简单的代码，不需要太多解释。我们以前也做过一个非常类似的代码。你还记得吗？那是在最初的几章，当我们正在制作一个浇水机器人时，我们必须在特定时间给植物浇水。现在它所做的就是检查时间，以及时间是否为`06`小时，分钟是否小于`20`。也就是说，灯会在 07:00 到 07:19 之间打开。之后，它会关闭。

# 制作令人讨厌的闹钟

但是有一个问题。问题是灯会打开，无论您是否起床，灯都会在 20 分钟内自动关闭。这有点问题，因为您并不是每次都会在 20 分钟内醒来。那么，在这种情况下，我们应该怎么办呢？我们需要做的第一件事是检测您是否醒来了。这非常简单，这里不需要太多解释。如果您早上醒来，非常肯定您会离开床。一旦您离开床，我们就可以检测到运动，告诉我们的自动系统您是否真的醒来了。

现在，我们可以在这里做一些非常简单的事情。我们可以检测您的动作，并根据检测结果决定您是否真的醒来了。这似乎不是什么大任务。我们只需要添加一个运动检测传感器。为此，我们可以使用 PIR 传感器，它可以告诉我们是否检测到了运动。所以，让我们继续，在我们的系统顶部添加另一层传感器，看看会发生什么。

首先，按以下方式连接电路。在安装 PIR 传感器时，请确保它面向床，并检测其周围的任何运动。一旦 PIR 设置好，将传感器连接如下图所示，并看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/e0c96c13-a539-42bc-bf6c-ae78bdad8e4c.png)

完成后，继续编写以下代码：

```py
import RPi.GPIO as GPIO import time LIGHT = 23 PIR = 24 Irritation_flag = 3  GPIO.setmode(GPIO.BCM) GPIO.setwarnings(False) GPIO.setup(LIGHT,GPIO.OUT) GPIO.setup(PIR, GPIO.IN) import datetime H = datetime.datetime.now().strftime('%H') M = datetime.datetime.now().strftime('%M')       while True:

        if H = '07' and M <= '15' and Iriitation_Flag > 0 and GPIO.input(PIR) == 0:

  GPIO.output(LIGHT,GPIO.HIGH)

  if H = '07'and GPIO.input(PIR)==1:

 GPIO.output(LIGHT,GPIO.LOW)
            time.sleep(10) Irritation_Flag = Irritation_Flag - 1  for H = '07'and M > '15' and Irritation_Flag > 0 and GPIO.input(PIR) = 0: GPIO.output(LIGHT,GPIO.HIGH)
            time.sleep(5) GPIO.output(LIGHT,GPIO.LOW)
            time.sleep(5)  if H != '07':

            Irritation_flag = 3
            GPIOP.output(LIGHT, GPIO.LOW)  
```

好的，让我们看看我们做了什么。代码非常简单，但我们在其中有一个小变化，那就是“烦躁标志”：

```py
Irritation_flag = 3
```

现在，这个变量的作用有点像贪睡按钮。我们知道，当我们醒来时，有时，或者事实上，大多数时候，我们会再次回去睡觉，直到很久以后才意识到我们迟到了。为了防止这种情况，我们有这个“烦躁标志”，它的基本作用是检测您停止闹钟的次数。我们稍后会看到它的使用方法：

```py
        if H = '07' and M <= '15' and Irritation_Flag > 0 and GPIO.input(PIR) == 0:

  GPIO.output(LIGHT,GPIO.HIGH)
```

在这一行中，我们只是比较小时和分钟的时间值。如果小时是`07`，分钟少于或等于`15`，那么灯将关闭。还有一个条件是`Irritation_Flag > 0`，因为我们在开始时已经声明了`Irritation_flag = 3`；因此，最初这个条件总是为真。最后一个条件是`GPIO.input(PIR) == 0`；这意味着只有当 PIR 没有检测到任何运动时，条件才会满足。简单地说，如果 PIR 没有检测到任何运动，那么闹钟将在每天 07:00 和 07:15 之间响起：

```py
  if H = '07'and GPIO.input(PIR)==1:

 GPIO.output(LIGHT,GPIO.LOW)
            time.sleep(10) Irritation_Flag = Irritation_Flag - 1
```

在程序的这一部分，只有当小时或`H`等于`7`并且 PIR 检测到一些运动时，条件才会为真。因此，每当时间在 07:00 和 07:59 之间，以及每当检测到运动时，条件就会为真。一旦为真，程序将首先使用`GPIO.output*LIGHT,GPIO.LOW`关闭灯。一旦关闭，它会使用`time.sleep(10)`等待`10`秒。时间到后，它将执行以下操作：`Irritation_Flag - Irritation_Flag - 1`。现在它所做的是每次检测到运动时将`Irritation_Flag`的值减少`1`。因此，第一次发生运动时，`Irritation_Flag`的值将为`2`；之后将为`1`，最后将为`0`。

如果你看一下代码的前一部分，你会发现只有当`Irritation_Flag`的值大于`0`时，灯才会打开。因此，如果你想关闭灯，你至少要移动三次。为什么是三次？因为代码`Irritation_Flag = Irritation - 1`将被执行三次，以使值减少到`0`，这显然会使条件`GPIO.input(PIR) > 0`为假：

```py
  for H = '07'and M > '15' and Irritation_Flag > 0 and GPIO.input(PIR) = 0: GPIO.output(LIGHT,GPIO.HIGH)
            time.sleep(5) GPIO.output(LIGHT,GPIO.LOW)
            time.sleep(5) 
```

现在，假设即使经过了所有这些，你仍然没有醒来。那么应该发生什么？我们在这里为您准备了一些特别的东西。现在，我们不是使用`if`条件，而是使用`for`循环。它将检查时间是否为`07`小时，分钟是否大于`15`，`Irritation_Flag > 0`，显然没有检测到运动。只要所有这些条件都为真，灯就会在之后打开`5`秒，使用`time.sleep(5)`保持打开。然后灯会再次打开。这将一直持续下去，直到条件为真，或者换句话说，直到时间在 07:15 和 07:59 之间。`Irritation)_Flag > 0`，也就是说，连续三次未检测到运动。在此期间，for 循环将继续打开和关闭灯。由于频繁的灯光闪烁，你醒来的机会非常高。这可能非常有效，但肯定不是最方便的。然而，无论多么不方便，它仍然比传统的闹钟要好：

```py
 if H != '07':

            Irritation_flag = 3
```

我们已经准备好了整个基于灯光的闹钟，可以在每天早上叫醒我们。但是，有一个问题。一旦关闭，`Irritation_Flag`的值将为`0`。一旦变为`0`，无论时间如何，灯都不会启动。因此，为了确保闹钟每天都在同一时间运行，我们需要将标志的值设置为大于`0`的任何数字。

现在，在前一行中，如果`H != '07'`，那么`Irritation_flag`将为`3`。也就是说，每当时间不是`07`小时时，`Irritation_Flag`的值将为`3`。

这很简单，不是吗？但我相信它会很好地确保你按时醒来。

# 让它变得更加恼人

您能完全依赖前面的系统吗？如果您真的能控制自己早上不想起床的情绪，那么，是的，您可以。但对于那些喜欢躺在床上并在按掉贪睡按钮后再次入睡的人来说，我相信您一定能找到一种方法来关闭灯光而不是真正醒来。因此，就像代码中一样，当检测到运动三次时，灯光会关闭。但运动可以是任何东西。您可以在床上挥手，系统会将其检测为运动，这将违背整个目的。那么现在我们该怎么办呢？

我们有一个解决方案！我们可以使用一种方法，确保您必须起床。为此，我们将使用我们之前在项目中使用过的红外近距传感器，并根据传感器的距离读数，我们可以检测您是否已经穿过了特定区域。这可能非常有趣，因为您可以将该传感器安装在床的另一侧，或者可能安装在浴室的门口，直到您穿过特定线路为止。系统不会关闭闹钟。所以让我们看看我们将如何做。首先，按照以下图表连接硬件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/4b798678-b477-4322-86ad-e480bc2a2583.png)

完成图表后，继续上传以下代码：

```py
import RPi.GPIO as GPIO import time import Adafruit_ADS1x15 adc0 = Adafruit_ADS1x15.ADS1115() GAIN = 1  adc0.start_adc(0, gain=GAIN)  LIGHT = 23 PIR = 24 Irritation_flag = 1 IR = 2 GPIO.setmode(GPIO.BCM) GPIO.setwarnings(False) GPIO.setup(LIGHT,GPIO.OUT) GPIO.setup(PIR, GPIO.IN)
GPIO.setup(IR. GPIO.IN) import datetime H = datetime.datetime.now().strftime('%H') M = datetime.datetime.now().strftime('%M')       while True:

  if H = '07' and M <= '15' and Iriitation_Flag > 0 and GPIO.input(PIR) == 0:

  GPIO.output(LIGHT,GPIO.HIGH)

  if H = '07'and GPIO.input(PIR)==1: M_snooze = datetime.datetime.now().strftime('%M')
   M_snooze = M_snooze + 5
 for M <= M_snoozeGPIO.output(LIGHT,GPIO.LOW) F_value = adc0.get_last_result()  F1 = (1.0  / (F_value /  13.15)) -  0.35

     time.sleep(0.1)

     F_value = adc0.get_last_result()  F2 = (1.0  / (F_value /  13.15)) -  0.35

     F_final = F1-F2 M = datetime.datetime.now().strftime('%M') if F_final > 25

         Irritation_flag = 0     for H = '07'and M > '15' and Irritation_Flag > 0 and GPIO.input(PIR) = 0: GPIO.output(LIGHT,GPIO.HIGH)
 time.sleep(5) GPIO.output(LIGHT,GPIO.LOW)
 time.sleep(5)  if H != '07':

 Irritation_flag = 1 
```

震惊了吗？这段代码似乎相当复杂，内部嵌套了条件，再加上更多的条件。欢迎来到机器人领域！这些条件构成了大部分机器人的编程。机器人必须不断观察周围发生的事情，并根据情况做出决策。这也是人类的工作方式，不是吗？

说了这么多，让我们看看我们实际上在这里做了什么。大部分代码基本上与上一个相同。主要区别在于编程部分的中间某处：

```py
  if H = '07' and M <= '15' and Iriitation_Flag > 0 and GPIO.input(PIR) == 0:

  GPIO.output(LIGHT,GPIO.HIGH)
```

我们会在时间介于 07:00 和 07:15 之间时打开灯光：

```py
  if H = '07'and GPIO.input(PIR)==1: M_snooze = datetime.datetime.now().strftime('%M')
   M_snooze = M_snooze + 5
```

在`07`点的时候，每当 PIR 传感器被触发，或者换句话说，PIR 传感器检测到任何运动，那么它将在`if`条件内执行一系列活动，包括通过函数`datetime.datetime.now().strftime('%M')`记录时间，然后将其存储在名为`M_snooze`的变量中。

在下一行，我们取出存储在`M_snooze`中的分钟值，并再加上`5`分钟。因此，`M_snooze`的值现在增加了`5`：

```py
 for M <= M_snooze 
```

现在，在我们之前使用的相同`if`条件中，我们放置了一个`for`循环，看起来像这样：`for M <= M_snooze`。但这是什么意思？在这里，我们所做的事情非常简单。`for`循环内的程序将继续运行，并且会一直保持在循环中，直到我们所述的条件为真。现在，这里的条件规定了只要`M`小于或等于`M_snooze`的时间，条件就会保持为真。正如您之前学到的，`M`是当前的分钟值，而`M_snooze`是循环开始时的`M`的值，增加了`5`。因此，循环将在开始时的`5`分钟内保持为真：

```py
 GPIO.output(LIGHT,GPIO.LOW) F_value = adc0.get_last_result()  F1 = (1.0  / (F_value /  13.15)) -  0.35

     time.sleep(0.1)

     F_value = adc0.get_last_result()  F2 = (1.0  / (F_value /  13.15)) -  0.35

     F_final = F1-F2
```

现在，这是程序中最有趣的部分。直到`for M <= M_snooze`为真，前面的代码行将运行。让我们看看它在做什么。在`F-value = adc0.get_last_result()`这一行中，它获取红外距离传感器的值并将其存储在`F_value`中。然后，在`F1 = (1.0/(F_value/13.15))-0.35`这一行中，我们简单地计算了以厘米为单位的距离。我们已经学习了这是如何发生的，所以这里不需要做太多解释。距离的值存储在一个名为`F1`的变量中。然后，使用`time.sleep(0.1)`函数，我们暂停程序`0.1`秒。然后，我们再次重复相同的任务；也就是说，我们再次获取距离的值。但是这次，计算出的距离值存储在另一个名为`F2`的变量中。最后，在所有这些都完成之后，我们计算`F_final`，即`F_final = F1 - F2`。所以我们只是计算了第一次和第二次读数之间的距离差。但是，你可能会问我们为什么要这样做。这有什么好处呢？

嗯，你还记得，我们把红外距离传感器放在浴室门口。现在，如果没有人经过，数值将保持相当恒定。但是每当有人经过时，距离就会发生变化。因此，如果从第一次到最后一次读数的总距离发生变化，那么我们可以说有人通过了红外传感器。

这很酷，但为什么我们不像以前那样保留一个阈值呢？答案很简单。因为如果你需要改变传感器的位置，那么你又需要根据位置重新校准传感器。所以这是一个简单但健壮的解决方案，可以在任何地方使用：

```py
 if F_final > 10

        Irritation_flag = 1
```

现在我们已经得到了读数，可以告诉我们是否有人经过。但是除非我们把它放在某个地方，否则这些数据是没有用的。

所以，在条件`if F_final > 10`中，每当距离变化超过`10`厘米时，条件就会成立，`Irritation_flag`将被设置为`1`。

如果你回到前面的行，你就会发现只有在时间在 07:00 和 07:15 之间，且`Irritation_flag`必须为`0`时，灯才会亮起。由于这个条件，我们通过将`Irritation_flag = 1`使条件的一部分变为假；因此，开灯的程序将不起作用。

现在，让我们回顾一下我们到目前为止所做的事情：

+   当时间是 07:00-07:15 时，灯将被打开

+   如果检测到有人移动，灯将被关闭

+   另一个条件将再持续五分钟，等待红外距离传感器检测到人体运动

+   如果一个人在五分钟内通过，那么警报将被停用，否则警报将再次开始打开灯

挺酷的，是吧？ 话虽如此，让我们从之前的程序中再添加另一个功能：

```py
  for H = '07'and M > '15' and Irritation_Flag = 0 and GPIO.input(PIR) = 0: GPIO.output(LIGHT,GPIO.HIGH)
    time.sleep(5) GPIO.output(LIGHT,GPIO.LOW)
    time.sleep(5)
```

你知道这是做什么的。如果在第一个`15`分钟内你不活动，也就是从 07:00 到 07:15，那么它将开始每五秒闪烁灯，迫使你醒来：

```py
 if H != '07':

            Irritation_flag = 0 
```

最后，我们使用条件`if H != '07':`。所以，每当`H`的值不是`07`时，条件就会成立，这将把`Irritation_flag`重置为`0`。到现在为止，你知道将`Irritation_flag`设置为`0`的作用。

# 总结

所以，最后，我们做出了我们的第一个迷你贾维斯，它可以在早上叫醒你，甚至在你没有按时醒来时还会惹你生气。希望你通过学习两个运动传感器及其在自动化电器中的应用来真正享受了这一章节。所以，继续在家里尝试一下，根据自己的需求修改代码，制作一些真正酷炫的东西。接下来，我们将让我们的贾维斯做一些更酷炫的事情，并且我们将介绍一些更令人兴奋的有关人体检测的东西。


# 第二十五章：用贾维斯识别人类

到目前为止，我们已经在上一章中了解到如何将多层条件组合在一起以获得所需的功能。我们刚刚完成了让贾维斯为您工作的第一步。现在，是时候让它变得更加强大了。

在本章中，我们将使其控制更多您家中的电子设备，这些设备可以在您没有告诉系统任何内容的情况下自主控制。所以，不要拖延，让我们直接进入并看看我们的收获。

# 打开灯，贾维斯

智能家居的基本功能之一是在您附近时为您打开灯光。这是任何系统可以为您做的最基本的事情之一。我们将从您进入房间时打开灯光开始，然后我们将使系统变得更加智能。

因此，我们需要做的第一件事是识别您是否在房间里。有多种方法可以做到这一点。生活的一个重要特征就是运动的存在。您可能会说植物不会移动，但它们会生长，不是吗？因此，检测运动可能是检测某人是否在场的关键步骤！

这一步对您来说并不那么困难，因为我们之前已经接口化了这个传感器。我们说的是老式的 PIR 传感器。因此，传感器将感知区域内的任何运动。如果有任何运动，那么贾维斯将打开灯光。我相信这是您现在可以自己做到的事情。您仍然可以参考这里的代码和电路图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/d18f3ec7-4d2a-452c-bf98-a522f1c87325.png)

现在上传以下代码：

```py
import RPi.GPIO as GPIO
import time
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
PIR = 24
LIGHT = 23
GPIO.setup(DOPPLER,GPIO.IN)
GPIO.setup(BUZZER,GPIO.OUT)
While True:
   if GPIO.input(PIR) == 1:
       GPIO.output(LIGHT,GPIO.HIGH)
   if GPIO.input(PIR) == 0:
       GPIO.output(LIGHT,GPIO.LOW)
```

在上述代码中，我们只是在检测到运动时立即打开灯光，但问题是它只会在有运动的时候打开灯光。这是什么意思？简单来说，只要有一些运动，灯就会保持开启，一旦运动停止，灯就会关闭。

对于想要减肥的人来说，这可能是一个很好的代码，但对于我们大多数人来说，这将是令人讨厌的。因此，让我们包含一个小循环，我们在上一章中使用过，并使其变得更好一些：

```py
import RPi.GPIO as GPIO
import time

GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)

PIR = 24
LIGHT = 23
TIME = 5

GPIO.setup(PIR,GPIO.IN)
GPIO.setup(BUZZER,GPIO.OUT)

While True:

   If GPIO.input(PIR) == 1:

       M = datetime.datetime.now().strftime('%M')
       M_final= M + TIME 
       for M < M_final:

         GPIO.output(LIGHT,GPIO.HIGH)
         M = datetime.datetime.now().strftime('%M')

         if GPIO.input(PIR) == 1:
            M_final = M_final + 1 if GPIO.input(PIR) = 0:

        GPIO.output(LIGHT, GPIO.LOW)} 
```

因此，在这个程序中，我们所做的就是添加了一个`for`循环，它会在设定的时间内打开灯光。这段时间有多长可以通过改变变量`TIME`的值来切换。

在那个循环中还有一个有趣的部分，如下所示：

```py
 if GPIO.input(PIR) == 1
            M_final = M_final + 1 
```

你可能会想为什么我们要这样做？每当灯光被打开时，它将保持开启 5 分钟。然后，它将关闭并等待运动发生。因此，基本上，这段代码的问题是，如果您在房间里，灯光打开后，它将在 5 分钟内查看是否有运动被检测到。有可能在 5 分钟后寻找运动时您正在运动。但大多数情况下，这不会发生。因此，我们使用 PIR 传感器来检测运动。每当检测到运动时，通过`M_final = M_final + 1`这一行来增加`M_final`的值，从而延长灯光打开的时间。

# 理解运动

到目前为止，您一定已经意识到 PIR 传感器并不是我们打开或关闭灯光的最理想传感器。主要是因为，尽管运动是存在的最佳指标之一，但有时您可能根本不会移动，例如休息、阅读书籍、观看电影等。

现在我们该怎么办？嗯，我们可以做一个小技巧。还记得在上一章中我们使用我们的接近传感器来感知一个人是否穿过了特定区域吗？我们将在这里植入类似的逻辑；但不只是简单地复制粘贴代码，我们将改进它，使其变得更好。

因此，我们将使用两个红外接近传感器，而不是使用一个。安装如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/ec73b93a-776b-4d21-b548-77a79d33417a.png)

现在很明显，每当有人从门边走进房间边时，**传感器 1**在检测到人体时会显示较低的读数。然后，当他朝房间一侧走去时，**传感器 2**将显示类似的读数。

如果首先触发**传感器 1**，然后触发**传感器 2**，那么我们可以安全地假设这个人是从门边走向房间边。同样，如果相反发生，那么可以理解这个人是从房间里走出去。

现在，这相当简单。但是我们如何在现实生活中实现它呢？首先，我们需要按以下方式连接电路：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/f26bc00c-738b-49c4-b2d2-9ab5ea6176f3.png)

一旦完成，上传以下代码：

```py
import GPIO library
import RPi.GPIO as GPIO
import time

import Adafruit_ADS1x15 adc0 = Adafruit_ADS1x15.ADS1115()   GAIN = 1
LIGHT = 23 adc0.start_adc(0, gain=GAIN) adc1.start_adc(1, gain=GAIN)

GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)

while True:

 F_value = adc0.get_last_result()  F1 = (1.0  / (F_value /  13.15)) -  0.35

   time.sleep(0.1)

 F_value = adc0.get_last_result()  F2 = (1.0  / (F_value /  13.15)) -  0.35

   F0_final = F1-F2

   if F0 > 10 :

        Time0 =  time.time()

 F_value = adc1.get_last_result()  F1 = (1.0  / (F_value /  13.15)) -  0.35

   time.sleep(0.1)

 F_value = adc1.get_last_result()  F2 = (1.0  / (F_value /  13.15)) -  0.35

   F1_final = F1-F2

   if F1 > 10: 

 Time1 =  time.time()

    if Time1 > Time0:

        GPIO.output(LIGHT, GPIO.HIGH)

    if Time1 < Time0:

        GPIO.output(LIGHT, GPIO.LOW)      }
```

现在，让我们看看我们在这里做了什么。和往常一样，大部分语法都非常简单明了。最重要的部分是逻辑。因此，让我们逐步了解我们在做什么。

```py
 F_value = adc0.get_last_result()  F1 = (1.0  / (F_value /  13.15)) -  0.35

   time.sleep(0.1)

 F_value = adc0.get_last_result()  F2 = (1.0  / (F_value /  13.15)) -  0.35
```

在上面的代码行中，我们正在获取红外接近传感器的值，并计算相应的距离，将该值存储在一个名为`F1`的变量中。一旦完成，我们将使用`time.sleep(0.1)`函数停止 0.1 秒。然后，我们再次从同一传感器读取并将值存储在名为`F2`的变量中。为什么我们要这样做？我们在之前的章节中已经理解了。

```py
 F0_final = F1-F2
```

一旦获得了`F1`和`F0`的值，我们将计算差值以找出是否有人通过。如果没有人通过，那么读数几乎相同，差异不会很大。但是，如果有人通过，那么读数将是相当大的，并且该值将存储在一个名为`F0_final`的变量中。

```py
 if F0 > 10 :

        Time0 =  time.time()
```

如果`F0`的值或第一次和第二次读数之间的距离差大于 10 厘米，则`if`条件将为真。一旦为真，它将将`Time0`变量的值设置为当前时间值。`time.time()`函数将记录下确切的时间。

```py
 F_value = adc1.get_last_result()  F1 = (1.0  / (F_value /  13.15)) -  0.35

   time.sleep(0.1)

 F_value = adc1.get_last_result()  F2 = (1.0  / (F_value /  13.15)) -  0.35 
```

```py
 F1_final = F1-F2   if F1 > 10: 

 Time1 =  time.time()
```

现在，我们将对**传感器 2**执行完全相同的步骤。这里没有什么新的要告诉的；一切都很简单明了。

```py
    if Time1 > Time0:

        GPIO.output(LIGHT, GPIO.HIGH)
```

一旦所有这些都完成了，我们比较`Time1 > Time0`。为什么我们要比较呢？因为`Time0`是**传感器 1**的记录时间。如果人在里面移动，那么**传感器 1**将首先被触发，然后**传感器 2**将被触发。因此，**传感器 2**的记录时间会更长，相对于**传感器 1**来说更早。如果发生这种情况，那么我们可以假设人正在进来。如果有人进来，我们只需要打开灯，这正是我们在这里要做的。

```py
    if Time1 < Time0:

        GPIO.output(LIGHT, GPIO.LOW)
```

同样，当一个人走出去时，首先触发的传感器将是**传感器 2**，然后将触发**传感器 1**。使得记录在`Time1`中的时间比`Time2`更早；因此，每当这个条件为真时，我们就会知道这个人正在离开房间，灯可以关闭。

继续安装在门附近，看看它的反应。我相信这将比我们之前通过 PIR 做的要好得多。玩得开心，并尝试找出它可能存在的任何缺陷。

# 完善运动

你能在以前的代码中找到任何缺陷吗？它们并不难找到；当房间里只有一个人时，代码运行得很好。但是如果安装在有多人出入的地方，可能会有挑战。这是因为每当有人走出去时，灯就会熄灭。

现在问题显而易见，是时候让代码变得更加智能了。为了做到这一点，硬件将保持完全相同；我们只需要让代码更加智能。让我们看看我们可以如何做到：

```py
import GPIO library
   import RPi.GPIO as GPIO
   import time
   import time
   import Adafruit_ADS1x15
   adc0 = Adafruit_ADS1x15.ADS1115()
GAIN = 1
 adc0.start_adc(0, gain=GAIN)
adc1.start_adc(1, gain=GAIN)
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
PCount = 0
while True:
   F_value = adc0.get_last_result()
   F1 = (1.0 / (F_value / 13.15)) - 0.35
   time.sleep(0.1)
   F_value = adc0.get_last_result()
   F2 = (1.0 / (F_value / 13.15)) - 0.35
   F0_final = F1-F2
   if F0 > 10 :
        Time0 = time.time()
   F_value = adc1.get_last_result()
   F1 = (1.0 / (F_value / 13.15)) - 0.35
   time.sleep(0.1)
   F_value = adc1.get_last_result()
   F2 = (1.0 / (F_value / 13.15)) - 0.35
   F1_final = F1-F2
   if F1 > 10:
        Time1 = time.time()
    if Time1 > Time0:
        PCount = PCount + 1
    if Time1 < Time0:
        PCount = PCount - 1

if PCount > 0:

           GPIO.output(LIGHT, GPIO.HIGH)
       else if PCount = 0:
          GPIO.output(LIGHT, GPIO.LOW)        
```

我们所做的是非常基础的。我们声明了一个名为`PCount`的变量。这个变量被声明为计算房间或家里的人数。正如你在代码的前几行中所看到的，我们声明了`PCount`的值为`0`。我们假设一旦我们开始，房间内的人数将为`0`。

```py
    if Time1 > Time0:

        PCount = PCount + 1
```

每当条件`if Time1 > Time0:`满足时，`PCount`的值就会增加`1`。众所周知，只有当有人在房子里走动时，条件才会成立。

```py
    if Time1 < Time0:

        PCount = PCount - 1
```

同样，当一个人在外面走的时候，条件`if Time1 < Time0:`是真的；每当这种情况发生时，`PCount`的值就会减少`1`。

```py
    if PCount > 0:

       GPIO.output(LIGHT, GPIO.HIGH)
```

现在我们已经开始计算房间内的人数，我们现在应用条件，如果`PCount`的数量大于`0`，则会打开。因此，当房屋内的人数大于`0`时，灯将亮起。

```py
    else if PCount = 0:

       GPIO.output(LIGHT, GPIO.LOW)
```

以非常相似的方式，如果`PCount`的值或者房屋内的人数达到`0`，灯将被关闭。

因此，完美！

# 控制强度

我们现在已经控制了很多灯。现在是时候控制我们的风扇和其他空气循环系统了。每当我们谈论风扇或任何其他空气循环设备时，本质上我们在谈论电机。正如我们之前学到的，电机是简单的设备，可以使用电机驱动器非常容易地进行控制。但是你知道，当时我们控制的是直流电机。直流电机是非常简单的设备。但是当我们谈论我们的家用电器时，那么大多数这些设备将使用交流电或交流电流。我假设你一定知道那是什么，以及它与直流电的区别。

现在你知道我们家用的电机是交流电机，你也必须考虑到他们的控制机制将与直流电机大不相同。如果你这样想，你是对的。然而，电子产品的好处是，没有什么真的困难或复杂。基本原理基本上是一样的。所以，让我们看看如何在交流电源中控制电机的速度。

正如我们之前所见，我们可以简单地给直流电机一个 PWM 信号，电机将以 PWM 信号的平均电压速度运行。现在，你一定在想，这也可以应用于交流。事实是，是的，如果你想控制灯或类似设备，这是可以做到的，这些设备在波形失真的情况下没有任何主要特性变化。然而，当我们谈论其他组件时，我们遇到了一个大问题。交流波形看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/e6c88285-4f38-493f-8a73-ab5d0a621507.png)

这基本上意味着电位定期变化。在大多数家庭中，这是每秒 50 次。现在，想象一下，如果我们有一个 PWM 控制的设备，它在特定间隔开关电路，只允许电源通过。然后，正弦波的不同部分将传递到最终输出。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/d3c74564-5890-4819-8bd8-c37da64c8c2c.png)

正如你在前面的 PWM 中所看到的，幸运的是 PWM 信号与交流电源的相位匹配；然而，由于这个原因，只有相位的正端被传输到最终输出，而不是负端。这将给我们的负载造成严重问题，有很大的机会连接的设备将无法工作。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/3d28446a-d7a4-4893-85e7-87dfa8a9a994.png)

我们还有另一个例子，其中 PWM 是随机的，它让波的随机部分通过。在这种情况下，我们可以清楚地看到随机地传输波的任何部分，正负端电压不同步，这将是一个巨大的问题。因此，我们不使用 PWM，而是使用一些非常有趣的东西。

最常用的方法称为**相位触发控制**。有时也称为相角控制或相位切割。它的本质是在相位的某些部分切割波，让其余的波通过。困惑吗？让我在这里给你展示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/047edc17-d0c2-4d67-9659-cf416b3bb5af.png)

现在，正如你所看到的，交流波的后半部分的相位被切割了，没有传递到最终输出。这使得最终输出只有总输入的 50%。这种技术的作用是，在减小总体输出电压的同时，保持电源的交流特性。同样，如下图所示，波在已经传递了 75%后被切割。这导致输出相对较低：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/3b77b2b6-78b7-4683-b2c7-eea349d43a3c.png)

现在你可能会问，我们到底是如何做到这一点的？这是通过一个相对复杂的电路来完成的，它检测波的相位角，然后打开或控制一个双向高功率半导体晶闸管。这导致电源在某些相位通过或停止。我们将把这个电路的确切工作留到下一次，因为它相当复杂，与本书无关。

现在来到基本点，我们知道相位切割是什么，我们也知道晶闸管是让我们做到这一点的基本设备。但如何使用树莓派来实现这一点是个问题。

首先，我们需要一个交流调光模块。这个模块已经具备了相位检测和切割的所有组件。所以我们需要做的就是简单地使用 PWM 来控制它。

虽然我可能不需要演示如何连接电路或代码应该是什么，但为了理解起见，让我们使用这个模块将灯泡连接到我们的 Arduino，然后控制灯泡。现在，首先要记住的是负载应该是灯泡，而不是其他任何东西，比如 LED 灯。所以继续按照下图所示连接电路：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/26e340ef-6b20-41d1-9951-8d8bd3b1850c.png)

完成后，上传以下代码：

```py
import RPi.GPIO as GPIO
import time                             
GPIO.setmode(GPIO.BCM)       
GPIO.setup(18,GPIO.OUT)         
I = 0
pwm= GPIO.PWM(18,50)

for I < 100:

    I = I+1
    pwm.start(I)
    time.sleep(0.1)

GPIO.cleanup()}
```

预期的是，连接的灯将首先微弱发光，然后逐渐增加强度，直到达到 100%。控制这样一个复杂的过程是如此简单。

# 智能温度控制

现在基础知识已经掌握，让我们继续使用这个系统构建有意义的东西。将空调设置到完美的温度是不是很困难？无论你做什么，最终都感觉不是最舒适的位置。这是由于身体在一天中温度的生理变化所致。

当你醒来时，你的体温相对较低。它比正常体温低多达 1°F。随着一天的进展，体温会上升，直到你上床睡觉。一旦你入睡，你的体温又开始下降，直到早上 4:00-6:00 达到最低点。这就是为什么当你上床睡觉时感觉温暖，但醒来时可能会感觉很冷的原因。现代空调有一个叫做睡眠模式的功能。它的作用是通过整个夜晚逐渐提高温度，这样你在任何时候都不会感到寒冷。但它的工作效果如何也是一个问题。

现在我们对机器人技术非常了解，我们将继续制作一个系统，来照顾一切。

在这部分，我们将空调和风扇连接在一起，这样它们可以一起工作，让你睡得更好。现在，在直接开始之前，我想让你看一下继电器上标明的额定值。正如你所看到的，继电器只能处理 250V 和 5 安培。现在，如果你查看空调的宣传册，你很容易就能明白我为什么要向你展示所有这些。空调的功耗将远远高于你的继电器所能承受的。因此，如果你尝试使用普通继电器来运行空调，那么你肯定会把继电器烧坏。你的电器可能的电流等级低于你的继电器。但是对于任何带有电机的设备，要记住该设备的初始功耗远高于额定功耗。因此，如果你的空调需要额定 10 安培，那么起动负载可能高达 15 安培。你可能会想，这不是问题，为什么我们不购买一个额定更高的继电器呢。好吧，正确！这正是我们将要做的。但是，电子设备的命名有时可能会很棘手。处理更高功率更高电压的电机开关设备通常被称为接触器，而不是继电器。从技术上讲，它们有相同的工作原理；然而，在这一点上的构造差异，这不是我们关心的问题。因此，我们将使用接触器来控制空调开关和调速器来控制风扇速度。既然这一点已经澄清，让我们继续并按照以下图表连接硬件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/44f748e3-7a93-46e6-afa7-765a6447d0ad.png)

```py
import RPi.GPIO as GPIO import time import Adafruit_DHT GPIO.setmode(GPIO.BCM) FAN = 18
AC = 17 pwm= GPIO.PWM(18,50)  GPIO.setup(FAN,GPIO.OUT) GPIO.setup(AC, GPIO.OUT)   while True: humidity, temperature = Adafruit_DHT.read_retry(sensor, pin)

    if temperature =>20 && temperature <=30: Duty = 50 + ((temperature-25)*10)
  pwm.start(Duty)

    if temperature <22 :

         GPIO.output(AC, GPIO.LOW)

    if temperature >= 24

         GPIO.output(AC, GPIO.HIGH)}

```

这里使用的逻辑非常基本。让我们看看它在做什么：

```py
 humidity, temperature = Adafruit_DHT.read_retry(sensor, pin)

    if temperature =>20 && temperature <=30: Duty = 50 + ((temperature-25)*10)
  pwm.start(Duty)
```

在这里，我们获取了`湿度`和`温度`的值。到目前为止一切都很好，但我们能否更进一步，使它变得更智能？以前的逻辑可能已经帮助你睡得更好，但我们能否让它对你来说更加完美？

我们身体中有多个指标可以让我们了解身体的状态。例如，如果你累了，你可能不会走得很快或者说得很大声。相反，你会做相反的事情！同样，有多个因素表明我们的睡眠周期是如何进行的。

其中一些因素是：体温、呼吸频率、快速动眼期睡眠和身体运动。测量准确的体温或呼吸频率和快速动眼期睡眠是一项挑战。但是当我们谈论身体运动时，我认为我们已经完善了。因此，基于身体运动，我们将感知我们的睡眠质量以及需要进行何种温度调节。

如果你注意到，每当有人睡觉并开始感到冷时，身体会呈胎儿姿势并且动作会少得多。这是自动发生的。然而，当一个人感到舒适时，会有一些不可避免的动作，比如翻身和手臂或腿部的运动。当一个人感到冷时，这是不会发生的。因此，通过这些动作，我们可以判断一个人是否感到冷。现在我们已经了解了身体的生理变化，让我们尝试围绕它构建一个程序，看看我们能实现什么。

为了做到这一点，首先，我们需要按照以下方式连接电路：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/48c7ea27-075b-4caa-9601-797e8dc31680.png)

完成这些后，继续编写以下代码：

```py
import RPi.GPIO as GPIO import time import Adafruit_DHT GPIO.setmode(GPIO.BCM) FAN = 18
AC = 17
PIR = 22 PIN = 11
Sensor = 4 pwm= GPIO.PWM(18,50)  GPIO.setup(FAN,GPIO.OUT) GPIO.setup(AC, GPIO.OUT)   while True: humidity, temperature = Adafruit_DHT.read_retry(sensor, pin) H = datetime.datetime.now().strftime('%H') 
M = datetime.datetime.now().strftime('%M')

    if H <= 6 && H <= 22:

        if M <=58 : M = datetime.datetime.now().strftime('%M') humidity, temperature = Adafruit_DHT.read_retry(sensor, pin)
 if GPIO.input(PIR) == 0 :

                Movement = Movement + 1
                time.sleep(10)

           if temperature < 28: if Movement > 5 :

                    Duty = Duty + 10 pwm.start(Duty)
                    Movement = 0     

        if M = 59 : 

            if Movement = 0 :

                Duty = Duty -10
                pwm.start(Duty)

            Movement = 0

        if temperature <22 :

           GPIO.output(AC, GPIO.LOW)

       if temperature >= 24 && H <= 6 && H >= 22:

           GPIO.output(AC, GPIO.HIGH)

        if temperature > 27

            pwm.start(100)

    for H > 7 && H < 20 

        GPIO.output(AC, GPIO.LOW)

    if H = 20 

        GPIO.output(AC,GPIO.HIGH)
  }
```

让我们来看看引擎盖下面发生了什么：

```py
 if H <= 6 && H <= 22:

        if M <=58 : M = datetime.datetime.now().strftime('%M') humidity, temperature = Adafruit_DHT.read_retry(sensor, pin)
```

你会看到的第一件事是我们有一个条件：`if H,= 6 && H<= 22:`。只有在时间范围在上午 10 点到晚上 6 点之间时，这个条件才会成立。这是因为这是我们通常睡觉的时间。因此，在这个条件下的逻辑只有在睡觉的时候才会起作用。

第二个条件是`如果 M <= 58`，只有当时间在`0`和`58`分钟之间时才为真。因此，当时间为`M = 59`时，这个条件将不起作用。我们将看到为什么要有这个逻辑的原因。

此后，我们正在计算时间并将值存储在一个名为`M`的变量中。我们还在计算湿度和温度值，并将其存储在名为`temperature`和`humidity`的变量中：

```py
 if GPIO.input(PIR) == 0 :

                Movement = Movement + 1
                time.sleep(10) 
```

现在，在这一行中，我们正在实施一个条件，如果从 PIR 读取到的值很高，那么条件将为真。也就是说，会检测到一些运动。每当这种情况发生时，`Movement`变量将增加`1`。最后，我们使用`time.sleep(10)`函数等待`10`秒。这是因为 PIR 可能会在短暂的时间内保持高电平。在这种情况下，条件将一遍又一遍地为真，从而多次增加`Movement`的值。

我们增加`Movement`的值的目的是为了计算人移动的次数。因此，在一个时间内多次增加它将违背这个目标。

```py
 if temperature < 28: if Movement > 5 :

                    Duty = Duty + 10 pwm.start(Duty)
                    Movement = 0
```

现在我们有另一个条件，即`如果温度<28`。对于条件何时为真，不需要太多解释。因此，每当条件为真，如果计数的`Movement`次数超过`5`，那么`Duty`的值将增加`10`。因此，我们将 PWM 发送到空调调光器，从而增加风扇的速度。最后，我们将`Movement`的值重置为`0`。

因此，我们只是在计算移动次数。只有当温度低于 28°C 时才计算这一移动。如果移动次数超过`5`，那么我们将增加风扇速度 10%。

```py
        if M = 59 : 

            if Movement = 0 :

                Duty = Duty -10
                pwm.start(Duty)

            Movement = 0
```

在前一节中，逻辑只有在时间在`0`和`58`之间时才有效，也就是计数将发生的时间。当`M`的值为`59`时，那么条件`if Movement = 0`将被检查，如果为真，那么`Duty`的值将减少`10`。这将减慢风扇的速度 10%。此外，一旦执行了这个条件，`Movement`的值将被重置为`0`。因此，下一个小时可以开始一个新的循环。

基本上，这意味着计数将以小时为单位进行。如果`Movement`超过`5`，那么`Duty`的值将立即增加。但是，如果不是这种情况，程序将等待直到分钟接近`59`的值，每当发生这种情况时，它将检查是否有任何运动，如果有，风扇速度将降低。

```py
        if temperature <22 :

           GPIO.output(AC, GPIO.LOW)

        if temperature >= 24 && H <= 6 && H >= 22: 

           GPIO.output(AC, GPIO.HIGH)

        if temperature > 27

            pwm.start(100)
```

所有这些代码都非常直接。如果温度低于`22`，则空调将关闭。此外，如果温度等于或超过`24`，并且时间在晚上 10:00 到早上 6:00 之间，则空调将打开。最后，如果温度超过`27`，则风扇将以 100%的速度打开。

```py
    for H > 7 && H < 20 

        GPIO.output(AC, GPIO.LOW)

    if H = 20 

        GPIO.output(AC,GPIO.HIGH)
```

最后，我们通过使用条件`for H > 7 && H <20`来确保在这段时间内空调始终处于关闭状态。此外，如果`H = 20`，则应打开空调，以便在准备睡觉之前冷却房间。

# 添加更多

正如你现在可能已经了解的那样，我们可以根据自己的需求控制任何空调电器。我们已经理解了开关，并且已经完善了我们可以改变灯光强度和风扇速度的方式。但你有没有注意到一件事？随着我们的系统变得越来越复杂，所需的 GPIO 数量将会增加。总有一个时刻，你会想要连接更多的设备到你的树莓派上；然而，由于物理端口的不足，你将无法这样做。

这在电子学中是非常常见的情况。和往常一样，这个问题也有解决方案。这个解决方案被称为复用器。复用器的基本工作是在任何计算机系统中扩大端口的数量。现在你一定在想，它是如何做到的呢？

这个概念非常简单。让我们首先看一下复用器的图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/aea10593-2bf8-4d57-9d45-65505431998a.png)

在上图中，您可以看到复用器有两端—一个是信号输出线，另一个是相对的。我们需要首先了解的是，复用器是一个双向设备，即它从复用器向连接的设备发送数据，反之亦然。

现在，首先是电源线，这很基本。它用于给复用器本身供电。然后，我们有**信号线**，它有两个端口，**Sig**和**EN**。**EN**代表使能，这意味着在**EN**不高的情况下，数据通信也不会发生。然后我们有一个叫做**Sig**的东西。这是连接到树莓派 GPIO 的用于数据通信的端口。接下来是选择线。正如您所看到的，我们有四个端口，分别是**S0**、**S1**、**S2**和**S3**。选择线的目的是选择需要选择的特定端口。以下是一个将澄清发生了什么的表：

| **S0** | **S1** | **S3** | **S4** | **选定输出** |
| --- | --- | --- | --- | --- |
| 0 | 0 | 0 | 0 | C0 |
| 1 | 0 | 0 | 0 | C1 |
| 0 | 1 | 0 | 0 | C2 |
| 1 | 1 | 0 | 0 | C3 |
| 0 | 0 | 1 | 0 | C4 |
| 1 | 0 | 1 | 0 | C5 |
| 0 | 1 | 1 | 0 | C6 |
| 1 | 1 | 1 | 0 | C7 |
| 0 | 0 | 0 | 1 | C8 |
| 1 | 0 | 0 | 1 | C9 |
| 0 | 1 | 0 | 1 | C10 |
| 1 | 1 | 0 | 1 | C11 |
| 0 | 0 | 1 | 1 | C12 |
| 1 | 0 | 1 | 1 | C13 |
| 0 | 1 | 1 | 1 | C14 |
| 1 | 1 | 1 | 1 | C15 |

在上表中，您可以看到通过在选择线上使用各种逻辑组合，可以寻址各种线路。例如，假设我们在选择引脚上有以下序列—S0 = 1，S1 = 0，S2 = 1，S3 = 1。如果这是来自树莓派的选择引脚的输入，那么将选择引脚号 C13。这基本上意味着现在 C13 可以与复用器的引脚**Sig**进行数据通信。此外，我们必须记住，使能引脚必须高才能进行数据传输。

以类似的方式，我们可以继续处理复用器的所有 16 个引脚。因此，从逻辑上看，通过使用树莓派的六个引脚，我们可以继续利用 16 个 GPIO。既然我们已经了解了复用的基础知识，让我们继续尝试使用其中的一个。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/d1d03c85-d1df-49df-8adb-5f7c95c895ed.png)

一旦硬件连接好了，让我们继续上传以下代码：

```py
import RPi.GPIO as GPIO import time  
GPIO.setmode(GPIO.BCM) GPIO.setwarnings(False) S0 = 21 S1 = 22 S2 = 23 S3 = 24 GPIO.setup(S0,GPIO.OUT) GPIO.setup(S1,GPIO.OUT) GPIO.setup(S2,GPIO.OUT) While True:  GPIO.output(S0,1) GPIO.output(S1,0) GPIO.output(S2,1) GPIO.output(S4,1) time.sleep(1) GPIO.output(S0,1) GPIO.output(S1,1) GPIO.output(S2,1) GPIO.output(S4,1) time.sleep(1) GPIO.output(S0,1) GPIO.output(S1,0) GPIO.output(S2,0) GPIO.output(S4,1) time.sleep(1) 'GPIO.output(S0,0) GPIO.output(S1,0) GPIO.output(S2,0) GPIO.output(S4,1) time.sleep(1) GPIO.output(S0,0) GPIO.output(S1,1) GPIO.output(S2,0) GPIO.output(S4,1) time.sleep(1) }
```

在这里，我们所做的实质上是，逐个触发选择线，以寻址 LED 连接的每个单个端口。每当发生这种情况时，相应的 LED 会发光。此外，它发光的原因是因为信号端`Sig`连接到树莓派的 3.3V。因此，向其连接的任何端口发送逻辑高电平。

这是复用器工作的基本方式之一。当我们使用多个设备和传感器时，这可能非常有用。

# 总结

在本章中，我们使 Jarvis 能够在不同条件下自动化您的家用电器，并将各种属性应用于系统。因此，请继续尝试许多其他情景，以增强您的家庭自动化系统。

在下一章中，我们将启用 Jarvis IoT，从而使用 Wi-Fi 和互联网从您的手机控制电器。


# 第二十六章：使贾维斯成为物联网设备

曾经我们曾经想象用手指控制世界。现在，这种想象已经成为现实。随着智能手机的出现，我们已经在做一些在十年前只能想象的事情。随着手机变得智能，行业和企业也尽力跟上这种颠覆性的变化。然而，仍然有一部分落后了。那是哪一部分？你的家！

想想你可以用智能手机控制家里的什么？并不多！有一些设备可以打开或关闭一堆设备，比如你的空调。然而，这个清单是详尽的。因此，凭借在前几章中获得的所有知识和我们手中强大的硬件，为什么我们不成为引领潮流和颠覆者，创造一些仍然只存在于我们想象中的东西呢。

本章将涵盖以下主题：

+   **物联网**（**IoT**）的基础知识

+   **消息队列遥测传输**（**MQTT**）协议

+   设置 MQTT 代理

+   制作基于物联网的入侵检测器

+   控制家庭

# 物联网的基础知识

在本章中，我们将使用智能手机控制家里的设备，但在这之前，我们应该了解这项技术的基础知识。本章的第一个主题是物联网——现代世界中被滥用的行话。这是每个人都想了解但却没有人知道的东西。物联网可以与一种技术相关联，你的冰箱会告诉你哪些物品供应不足，并会自动为你订购。可怜的东西！这项技术还需要一些时间来进入我们的家。但物联网不仅仅意味着这个。物联网是一个非常广泛的术语，几乎可以应用于所有的地方进行优化。那么，物联网是什么呢？

让我们来解释一下这个缩写，**物联网**，有时也被称为网络物理系统。那么，什么是**物**？在这里，任何有能力在没有人类干预的情况下收集或接收数据的电子物体都可以被称为物。因此，这个物可以是你的手机、心脏起搏器、健康监测设备等等。唯一的*条件*是它必须连接到互联网并具有收集和/或接收数据的能力。第二个术语是**互联网**；互联网指的是互联网，废话！现在，所有这些物联网设备都会向云端或中央计算机发送和接收数据。它之所以这样做，是因为任何物联网设备，无论大小，都被认为是资源受限的环境。也就是说，资源，比如计算能力，要少得多。这是因为物联网设备必须简单和便宜。想象一下，你必须在所有的路灯上安装物联网传感器来监控交通。如果设备的成本是 500 美元，那么安装这种设备是不切实际的。然而，如果它可以做到 5-10 美元，那么没有人会在意。这就是物联网设备的问题；它们非常便宜。现在，这个故事的另一面是，它们没有很多计算能力。因此，为了平衡这个方程，它们不是在自己的处理器上计算原始数据，而是将这些数据简单地发送到云计算设备或者服务器，这些数据在那里被计算，得出有意义的结果。所以，这样就解决了我们所有的问题。嗯，不是！这些设备的第二个问题是它们也可以是电池操作的一次性设备。例如，在森林的各个地方安装了温度传感器；在这种情况下，没有人会每周去更换电池。因此，这些设备是这样制作的，它们消耗很少甚至几乎没有电力，从而使编程变得非常棘手。

现在我们已经了解了物联网的概念，在本章中，我们将使我们的家居具备物联网功能。这意味着，我们将能够从家中的传感器接收和收集数据，在我们的移动设备上查看数据，并且如果需要，我们也可以使用智能手机控制设备。不过有一点，我们不会在云端进行计算，而是简单地将所有数据上传到云端，只需访问该数据或将我们的数据发送到云端，然后可以访问。我们将在另一本书中讨论云计算方面，因为这可能是一个全新的维度，超出了本书的范围。

# MQTT 协议

MQTT 是 ISO 认证的协议，被广泛使用。这个协议的有趣之处在于，它是由 Andy Stanford 和 Arlen Nipper 于 1999 年为监控沙漠中的油管开发的。您可以想象，在沙漠中，他们开发的协议必须是节能和带宽高效的。

这个协议的工作方式非常有趣。它具有发布-订阅架构。这意味着它有一个中央服务器，我们也称之为代理。任何设备都可以向该代理注册并发布任何有意义的数据。现在，被发布的数据应该有一个主题，例如，空气温度。

这些主题特别重要。为什么，您可能会问？对于代理，可以连接一个或多个设备。连接时，它们还需要订阅一个主题。假设它们订阅了主题*Air-*Temperature。现在，每当有新数据到来时，它都会发布到订阅设备。

需要知道的一件重要事情是，与 HTTP 中的请求不同，无需请求来获取代理的数据。相反，每当接收到数据时，它将被推送到订阅该主题的设备。很明显，TCP 协议也将一直处于工作状态，并且与代理相关的端口将始终连接以实现无缝的数据传输。但是，如果数据中断，代理将缓冲所有数据，并在连接恢复时将其发送给订阅者。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/ce8f2b8a-d40d-4856-b691-6970e0a04005.png)

如您所见，运动传感器和温度传感器通过特定主题即**Temperature**和**Motion**向 MQTT 服务器提供数据。订阅这些主题的人将从此设备获取读数。因此，实际传感器和移动设备之间不需要直接通信。

整个架构的好处是，可以连接无限数量的设备，并且不需要任何可扩展性问题。此外，该协议相对简单，即使处理大量数据也很容易。因此，这成为物联网的首选协议，因为它为数据生产者和数据接收者之间提供了一种简单、可扩展和无缝的连接。

# 设置 MQTT 代理

在这个主题中，让我们看看我们需要做什么来设置这个服务器。打开命令行，输入以下命令：

```py
sudo apt-get update
sudo apt-get upgrade
```

一旦更新和升级过程完成，继续安装以下软件包：

```py
sudo apt-get install mosquitto -y
```

这将在您的树莓派上安装 Mosquitto 代理。该代理将负责所有数据传输：

```py
sudo apt-get install mosquitto-clients -y
```

现在，这行将安装客户端软件包。您可以想象，树莓派本身将是代理的客户端。因此，它将处理必要的事情。

我们现在已经安装了软件包；是的，确切地说，就是这么简单。现在，我们需要做的就是配置 Mosquitto 代理。要做到这一点，您需要输入以下命令：

```py
sudo nano etc/mosquitto/mosquitto.conf
```

现在，这个命令将打开保存 Mosquitto 文件配置的文件。要进行配置，您需要到达此文件的末尾，您将看到以下内容：

```py
include_dir/etc/mosquitto/conf.d
```

现在，您可以通过在这些行之前添加`#`来注释掉前面的代码行。完成后，继续添加以下行：

```py
allow_anonymous false

password_file /etc/mosquitto/pwfile

listener 1883
```

让我们看看我们在这里做了什么。`allow_anonymous false`这一行告诉经纪人不是每个人都可以访问数据。接下来的一行，`password_file /etc/mosquitto/pwfile`告诉经纪人密码文件的位置，位于`/etc/mosquitto/pwfile`。最后，我们将使用`listener 1883`命令定义这个经纪人的端口，即`1883`。

最后，我们已经完成了在树莓派中设置 MQTT 客户端。现在我们准备继续并将其用于物联网启用的家庭。

# 制作基于物联网的入侵检测器

现在树莓派已经设置好，我们准备将其启用物联网，让我们看看我们将如何连接系统到互联网并使其正常工作。首先，我们需要将树莓派连接到我们想使用物联网技术控制的设备。所以继续使用以下图表进行连接：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/7fa73dbb-b3fd-4494-9b69-ac9943103add.png)

一旦您设置好所有的组件，让我们继续上传以下代码：

```py
import time  import paho.mqtt.client as mqtt import RPi.gpio as gpio
pir = 23
gpio.setmode(gpio.BCM)
gpio.setup(pir, gpio.IN)
client = mqtt.Client() broker="broker.hivemq.com" port = 1883
pub_topic = "IntruderDetector_Home" def SendData():
  client.publish(pub_topic,"WARNING : SOMEONE DETECTED AT YOUR PLACE")   def on_connect(client, userdata, flag,rc):
  print("connection returned" + str(rc))   SendData() while True:
 client.connect(broker,port) client.on_connect = on_connect   if gpio.output(pir) == gpio.HIGH :
    SendData() client.loop_forever() 
```

与迄今为止我们看到的其他代码块不同，这段代码对你来说可能会很新。所以我将解释除一些明显的部分之外的每个部分。所以，让我们看看我们在这里有什么：

```py
import paho.mqtt.client as mqtt
```

在这部分，我们将`pho.mqtt.client`库导入为`mqtt`。所以每当需要访问这个库时，我们只需要使用`mqtt`这一行，而不是整个库的名称。

```py
client = mqtt.Client()
```

我们使用`mqtt`库的`client`方法定义了一个客户端。这可以通过`client`变量来调用。

```py
broker="broker.hivemq.com"
```

所以我们正在程序中定义经纪人。对于这个程序，我们使用的经纪人是`broker.hivemq.com`，它为我们提供了经纪人服务。

```py
port = 1883
```

现在，我们将再次定义协议将工作的端口，即在我们的情况下是`1883`。

```py
pub_topic = "IntuderDetector_Home"
```

在这里，我们定义了名为`pub_topic`的变量的值，即`IntruderDetector_Home`。这将是在代码运行时可以订阅的最终主题。

```py
def SendData():
 client.publish(pub.topic, "WARNING : SOMEONE DETECTED AT YOUR PLACE")
```

在这里，我们定义了一个名为`SendData()`的函数，将数据`Warning : SOMEONE DETECTED AT YOUR PLACE`发布到我们之前声明的主题的经纪人。

```py
def on_message(client, userdata, message):
  print('message is : ')
 print(str(message.payload)) 
```

在这一行中，我们定义了一个名为`on_message()`的函数，它将打印一个值`message is :`，后面跟着数据是什么。这将使用`print(str(message.payload))`这一行来完成。它的作用是打印传递给函数参数的任何内容。

```py
 def on_connect(client, userdata, flag,rc):

     print("connection returned" + str(rc)) 
  SendData()
```

在这一行中，我们定义了`on_connect()`函数，它将打印`connection returned`一行，后面跟着`rc`的值。`rc`代表返回码。所以，每当消息被传递时，都会生成一个代码，即使没有，也会返回特定的代码通知错误。所以，可以将其视为确认。完成后，我们之前定义的`SendData()`函数将用于将数据发送到经纪人。

```py
client.connect(broker,port)
```

`connect()`是 MQTT 库的一个函数，它将客户端连接到经纪人。这很简单。我们只需要传递我们想要连接的经纪人的参数和要使用的端口。在我们的情况下，`broker = broker.hivemq.com`和`port = 1883`。所以当我们调用这个函数时，树莓派就连接到我们的经纪人了。

```py
client.on_connect = on_connect 
```

这是程序的核心。`client.on_connect`函数所做的是，每当树莓派连接到经纪人时，它就开始执行我们定义的`on_connect`函数。这将连续不断地将数据发送到经纪人，每隔 5 秒一次，就像我们在函数中定义的方式一样。这个过程也被称为回调，它使其成为事件驱动。也就是说，如果它没有连接，它就不会尝试将数据发送到经纪人。

```py
  if gpio.output(pir) == HIGH :
        sendData()
```

当 PIR 传感器变高或者检测到运动时，将调用`sendData()`函数，消息将被发送到代理，警告有人在你的地方被探测到。

```py
client.loop_forever()
```

这是我最喜欢的功能，特别是因为它有可爱的名字。正如你所期望的，`client.loop_forver()`函数将继续寻找任何事件，每当检测到事件时，它将触发数据发送到代理。现在我们将看到这些数据的部分。为此，我们需要从 App Store（如果你使用 iOS）或 Playstore（如果你使用 android）下载*MyMQTT*应用程序。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/3fb1bc6b-f76b-420f-8552-dd40ca79ea66.jpeg)

一旦你启动应用程序，你将看到上面的屏幕。你需要填写代理 URL 的名称，在我们的例子中是`broker.hivemq.com`。然后，填写端口，在我们的例子中是`1883`。

完成后，你将看到一个类似以下的屏幕：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/d328cb27-6910-4078-8afc-5119e25e41df.jpeg)

只需添加你需要的订阅名称，即`IntruderDetector_Home`。完成后，你将看到魔法发生！

在下一节中，我们将基于物联网来控制事物；到时见。

# 控制家庭

最后，使用以下图表进行连接并上传以下代码：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/1fe8d775-6898-4fa5-b7bf-e20e87071fcc.png)

```py
import time
import paho.mqtt.client as paho
import RPi.GPIO as GPIO
GPIO.setmode(GPIO.BCM)
GPIO.setup(14,GPIO.OUT)
broker="broker.hivemq.com"
sub_topic = light/control
client = paho.Client()
def on_message(client, userdata, message):
    print('message is : ')
    print(str(message.payload))
    data = str(message.payload)
    if data == "on":
        GPIO.output(3,GPIO.HIGH)
    elif data == "off":
        GPIO.output(3,GPIO.LOW)

def on_connect(client,userdata, flag, rc):
    print("connection returned" + str(rc))
    client.subscribe(sub_topic)
client.connect(broker,port)
client.on_connect = on_connect
client.on_message=on_message
client.loop_forever()
```

现在，在这段代码中，我没有太多需要告诉你的；它非常直接了当。我们发送数据就像上次一样。然而，这次我们使用了一个新的函数。所以，让我们看看这段代码到底是什么：

```py
def on_message(client, userdata, message):
       print('message is : ')
 print(str(message.payload)) data = str(message.payload) if data == "on": GPIO.output(3,GPIO.HIGH) elif data == "off": GPIO.output(3,GPIO.LOW)
```

在这里，我们定义了`on_message()`函数在做什么。函数有三个参数，消息将在这些参数上工作。这包括`client`，我们之前已经声明过；`userdata`，我们现在没有使用；最后是`message`，我们将通过智能手机通过互联网发送。

一旦你查看程序内部，这个函数将使用`print('message is : ')`和`print(str(message.payload))`来打印消息。完成后，`data`的值将被设置为订阅者发送的消息。

这些数据将由我们的条件来评估。如果数据保持`on`，那么 GPIO 端口号`3`将被设置为`HIGH`，如果字符串是`off`，那么 GPIO 端口号`3`将被设置为`LOW`—简单来说，打开或关闭你的设备。

```py
def on_connect(client,userdata, flag, rc):
    print("connection returned" + str(rc))
    client.subscribe(sub_topic)
```

我们之前也定义了`on_connect()`函数。然而，这次有些不同。我们不仅打印连接返回的值`rc`，还使用了另一个名为`client.subscribe(sub_topic)`的函数，它将让我们在程序中之前定义的特定主题上连接到代理。

```py
client.on_message=on_message
```

由于整个算法是基于事件驱动系统，这个`client.on_message`函数将一直等待接收消息。一旦接收到，它将执行`on_message`函数。这将决定是否打开或关闭设备。

要使用它，只需继续发送基于主题的数据，它将被你的树莓派接收。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/88174504-1729-4472-8917-f6a4f2ac0ab3.jpeg)

一旦接收到，决策函数`on_message()`将决定 MyMQTT 应用程序接收到了什么数据。如果接收到的数据是`on`，那么灯将被打开。如果接收到的数据是`off`，那么灯将被关闭。就是这么简单。

# 总结

在本章中，我们已经了解了物联网的基础知识以及 MQTT 服务器的工作原理。我们还制作了一个入侵者检测系统，无论你身在何处，只要有人进入你的家，它都会提醒你。最后，我们还创建了一个系统，可以通过简单的手机命令打开家中的设备。在下一章中，我们将让贾维斯能够让你根据你的声音与系统交互。


# 第二十七章：给 Jarvis 发声

曾经想过是否可以使用机器人来完成我们的工作吗？是的！在一些高科技小说或漫威电影甚至漫画书中肯定是可能的。所以，系好安全带，准备好迎接这个令人惊叹的章节，在这里，您将实际实现我刚才提到的内容。

本章将涵盖以下主题：

+   基本安装

+   自动交付答录机

+   制作一个交互式门答录机器人

+   让 Jarvis 理解我们的声音

# 基本安装

有各种方法和方法可以控制我们的智能家居 Jarvis，其中一些我们之前已经探讨过，比如通过控制它。因此，首先，我们需要准备我们的系统以能够进行语音合成；为此，让我们执行以下过程。

首先，转到终端并输入以下命令：

```py
sudo apt-get install alsa-utils
```

这将安装依赖项`alsa-utils`。`alsa-utils`包包含各种实用程序，用于控制您的声卡驱动程序。

完成后，您需要编辑文件。为此，我们需要打开文件。使用以下命令：

```py
sudo nano /etc/modules
```

完成后，将打开一个文件；在该文件的底部，您需要添加以下行：

```py
snd_bcm2835
```

您不需要深究我们为什么这样做。它只是用来设置事情。我可以给你解释；但是，在这个激动人心的时刻，我不想让你感到无聊。

此外，如果你幸运的话，有时你可能会发现该行已经存在。如果是这种情况，就让它在那里，不要动它。

现在，要播放我们需要 Jarvis 说的声音，我们需要一个音频播放器。不，不是你家里的那种。我们说的是能够播放的软件。

要安装播放器，我们需要运行以下命令：

```py
sudo apt-get install mplayer
```

好了，我们已经完成了音频播放器；让我们看看接下来要做什么。现在，我们需要再次编辑媒体播放器的文件。我们将使用相同的步骤打开文件并编辑它：

```py
sudo nano /etc/mplayer/mplayer.conf
```

这将打开文件。与之前一样，只需添加以下行：

```py
nolirc=yes
```

最后，我们需要给它一些声音，所以运行以下命令：

```py
sudo apt-get install festvox-rablpc16k
```

这将为 Jarvis 安装一个 16 kHz 的英国男声。我们喜欢英国口音，不是吗？

完美。一旦我们完成了之前提到的所有步骤，我们就可以开始了。要测试声音，只需将 USB 扬声器连接到树莓派并运行以下代码：

```py
import os
from time import sleep
os.system('echo "hello! i am raspberry pi robot"|festival --tts ')
sleep(2)
os.system('echo "how are you?"| festival --tts ')
sleep(2)
os.system('echo "I am having fun."| festival --tts ')
sleep(2)
```

好了，让我们看看我们实际做了什么：

```py
import os
```

您可能已经发现，我们正在导入名为`os`的库。该库提供了一种使用操作系统相关功能的方法：

```py
os.system('echo "Hello from the other side"|festival --tts ')
```

在这里，我们使用了一个名为`system()`的方法；它的作用是执行一个 shell 命令。也许你会想知道这是什么。shell 命令是用户用来访问系统功能并与之交互的命令。所以现在我们想要将文本转换为语音，我们将向这个函数提供两个参数。首先，文本是什么？在我们的例子中，它是`Hello from the other side`；我们这里的第二个参数是`festival --tts`。现在`festival`是一个库，`tts`代表文本到语音转换。因此，当我们将其传递给参数时，系统将知道要将传递给参数的文本从文本转换为语音。

就是这样！是的，就是这样。这就是我们让您的树莓派说话所需做的一切。

# 自动交付答录机

如今，我们都在网上订购东西。然而，无论亚马逊的流程有多么自动化，在谈论 2018 年时，我们仍然有人类将包裹送到我们的门口。有时，你希望他们知道一些关于放置包裹的地方。现在我们变得越来越自动化，过去你可能会在大门外留个便条的日子已经一去不复返了。是时候用我们的技术做些有趣的事情了。要做到这一点，我们几乎不需要做任何严肃的事情。我们只需要按照以下图示连接组件即可：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/b7b909b5-f145-40fc-bdb1-3d49aa5ffab9.png)

PIR 传感器必须放置在大门周围有运动时产生逻辑高电平的位置。

完成后，继续上传以下代码：

```py
import RPi.GPIO as GPIO
import time
Import os
GPIO.setmode(GPIO.BCM)
PIR = 13
GPIO.setup(PIR,GPIO.IN)
while True:

  if GPIO.input(PIR) == 1 :
     os.system('echo "Hello, welcome to my house"|festival --tts ')
     time.sleep(0.2)
     os.system('echo "If you are a delivery agent then please leave the package here"|festival --tts ')
     time.sleep(0.2)
     os.system('echo "If you are a guest then I'm sorry I have to leave I will be back after 7pm"|festival --tts ')
     time.sleep(0.2)
     os.system('echo "also Kindly don't step over the grass, its freshly grown and needs some time"|festival --tts ')
     time.sleep(1)
     os.system('echo "Thank you !"|festival --tts ')
```

现在我们所做的非常简单。一旦 PIR 传感器产生逻辑高电平，就会发出特定的指令。无需解释。如果需要澄清，可以参考之前的代码。

# 制作一个互动门 - 回答机器人

在上一章中，我们使用了 PIR 传感器来感知任何人类活动，然而传感器的问题是，无论谁来了或离开了，它都会传递相同的消息。这基本上意味着，即使你在漫长的一天后回家，它最终也会问同样的问题。相当愚蠢，是吧？

因此，在本章中，我们将使用之前的存储库，将视觉和语音整合在一起，形成一个令人惊叹的二人组。在这个过程中，摄像头将识别大门上的人，并且会识别是否是人类和陌生人，如果是的话，它会传递你打算传达的消息。另一方面，如果是你，它会简单地让你通过并问候。但是，如果检测到人脸但无法识别，则会向站在摄像头前的人提供一系列指令。

要实现这一切，你只需要在门口安装一个摄像头和 PIR。PIR 基本上是用来激活摄像头的。换句话说，只有在检测到运动时摄像头才会被激活。这个设置非常简单，不需要使用任何 GPIO。只需固定摄像头和 PIR，然后上传以下代码即可。

```py
import RPi.GPIO as GPIO
import time
Import os
import cv2
import numpy as np
import cv2

faceDetect = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
cam = cv2.VideoCapture(0)
rec = cv2.face.LBPHFaceRecognizer_create()
rec.read("recognizer/trainningData.yml")
id = 0

while True:

  GPIO.setmode(GPIO.BCM)
PIR = 13
GPIO.setup(PIR, GPIO.IN)

if GPIO.input(PIR) == 1:

  ret, img = cam.read()
gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
faces = faceDetect.detectMultiScale(gray, 1.3, 5)
for (x, y, w, h) in faces:
  cv2.rectangle(img, (x, y), (x + w, y + h), (0, 0, 255), 2)
id, conf = rec.predict(gray[y: y + h, x: x + w])

if id == 1:
  id = "BEN"
os.system('echo "Hello, welcome to the house BEN"|festival --tts ')
time, sleep(0.2)

else :

  os.system('echo "If you are a delivery agent then please leave the package here"|festival --tts ')
time, sleep(0.2)

os.system('echo "If you are a guest then I'
    m sorry I have to leave I will be back after 7 pm "|festival --tts ')
    time, sleep(0.2)

    os.system('echo "also Kindly don'
      t step over the grass, its freshly grown and needs some time "|festival --tts ')
      time.sleep(1)

      os.system('echo "Thank you !"|festival --tts ') cv2.imshow("face", img) if cv2.waitKey(1) == ord('q'):
      break cam.release()

      cv2.destroyAllWindows()
```

```py
faceDetect = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
```

在上述代码中，我们使用`CascadeClassifier`方法创建级联分类器，以便摄像头可以检测到人脸。

```py
cam = cv2.VideoCapture(0)
rec = cv2.face.LBPHFaceRecognizer_create()
```

在上述代码中，我们使用`cv2`的`VideoCapture(0)`方法从摄像头读取帧。此外，正在创建人脸识别器以识别特定的人脸。

```py
 ret, img = cam.read()
```

现在使用`cam.read()`从摄像头读取数据，就像在之前的代码中所做的那样。

```py
gray = cv2.cvtColor(img,cv2.COLOR_BGR2GRAY)
faces = faceDetect.detectMultiScale(gray,1.3,5)
```

图像被转换为灰色。然后，`faceDetect.detectMultiScale()`将使用灰色转换的图像。

```py
 for (x,y,w,h) in faces:
     cv2.rectangle(img, (x,y), (x+w, y+h), (0,0,255), 2)
     id, conf = rec.predict(gray[y:y+h, x:x+w])
     if id==1:
         id = "BEN" 
         os.system('echo "Hello, welcome to my house BEN"|festival --tts ')
         time, sleep(0.2)
```

当检测到人脸时，包含人脸的图像部分将被转换为灰色并传递给预测函数。该方法将告诉我们人脸是否被识别，如果识别出人脸，还会返回 ID。假设这个人是`BEN`，那么 Jarvis 会说`你好，欢迎来到我的家 BEN`。现在`BEN`可以告诉 Jarvis 打开灯，然后当唤醒词 Jarvis 被激活时，Jarvis 会做出回应。如果识别不出这个人，那么可能是个快递员。然后，执行以下命令：

```py
os.system('echo "If you are a delivery agent then please leave the package here"|festival --tts ')
time, sleep(0.2)

os.system('echo "If you are a guest then I'm sorry I have to leave I will be back after 7pm"|festival --tts ')
 time, sleep(0.2)

os.system('echo "also Kindly don't step over the grass, its freshly grown and needs some time"|festival --tts ')
time.sleep(1)

os.system('echo "Thank you !"|festival --tts ')
```

# 让 Jarvis 理解我们的声音

声音是沟通的本质。它帮助我们在很短的时间内传输大量数据。它肯定比打字更快更容易。因此，越来越多的公司正在努力制作能够理解人类语音和语言并根据其工作的系统。这绝对不容易，因为语言中存在着巨大的变化；然而，我们已经走了相当长的路。因此，不用花费太多时间，让我们的系统准备好识别我们的声音。

因此，在这里，我们将使用来自 Google Voice 的 API。您可能知道，Google 非常擅长理解您说的话。非常字面意思。因此，使用他们的 API 是有道理的。现在，它的工作方式非常简单。我们捕获声音，然后将其转换为文本。然后，我们比较文本是否与配置文件中定义的内容相似。如果匹配任何内容，则将执行与其关联的 bash 命令。

首先，我们需要检查麦克风是否连接。为此，请运行以下命令：

```py
lsusb
```

此命令将显示连接到 USB 的设备列表。如果您在列表上看到自己的设备，那么很好，您走上了正确的道路。否则，请尝试通过连接找到它，或者尝试其他硬件。

我们还需要将录音音量设置为高。要做到这一点，请继续输入以下命令：

```py
alsamixer
```

现在一旦 GUI 弹出到屏幕上，使用箭头键切换音量。

最好由您自己听取录制的声音，而不是直接将其传输到树莓派。为此，我们首先需要录制我们的声音，因此需要运行以下命令：

```py
arecord -l
```

这将检查摄像头是否在列表中。然后，输入以下命令进行录制：

```py
arecord -D plughw:1,0 First.wav
```

声音将以`First.wav`的名称记录。

现在我们也想听一下我们刚刚录制的声音。这样做的简单方法是输入以下命令：

```py
aplay test.wav
```

检查声音是否正确。如果不正确，您可以自由调整系统。

一旦我们完成了检查声音和麦克风，就该安装真正的工作软件了。有简单的方法可以做到这一点。以下是您需要运行的命令列表：

```py
wget –- no-check-certificate “http://goo.gl/KrwrBa” -O PiAUISuite.tar.gz

tar -xvzf PiAUISuite.tar.gz

cd PiAUISuite/Install/

sudo ./InstallAUISuite.sh
```

现在当您运行此程序时，将开始发生非常有趣的事情。它将开始向您提出各种问题。其中一些将是直截了当的。您可以用正确的思维以是或否的形式回答。其他可能非常技术性。由于这些问题可能随时间而变化，似乎没有必要明确提及您需要填写的答案，但作为一个一般的经验法则——除非您真的想说不，否则给出肯定的答案。

好了，我们已经安装了软件。现在在继续进行该软件之前，让我们继续编写以下程序：

```py
import RPi.GPIO as GPIO
import time
import os
GPIO.setmode(GPIO.BCM)
LIGHT = 2
GPIO.setup(LIGHT,GPIO.OUT)
GPIO.output(LIGHT, GPIO.HIGH)
os.system('echo "LIGHTS TURNED ON "|festival --tts')
```

每当此程序运行时，连接到 PIN 号为`2`的灯将被打开。此外，它将朗读`灯已打开`。将此文件保存为`lighton.py`：

```py
import RPi.GPIO as GPIO
import time
import os
GPIO.setmode(GPIO.BCM)
LIGHT = 23
GPIO.setup(LIGHT,GPIO.OUT)
GPIO.output(LIGHT, GPIO.LOW)
os.system('echo "LIGHTS TURNED OFF "|festival --tts')
```

同样，在此程序中，灯将被关闭，并且它将朗读`灯已关闭`。将其保存为`lightoff.py`：

```py
import RPi.GPIO as GPIO
import time
Import os
GPIO.setmode(GPIO.BCM)
FAN = 22
GPIO.setup(FAN,GPIO.OUT)
GPIO.output(LIGHT, GPIO.HIGH)
os.system('echo "FAN TURNED ON "|festival --tts')
```

现在我们也为风扇做同样的事情。在这个中，风扇将被打开；将其保存为`fanon.py`：

```py
import RPi.GPIO as GPIO
import time
Import os
GPIO.setmode(GPIO.BCM)
FAN = 22
GPIO.setup(FAN,GPIO.OUT)
GPIO.output(LIGHT, GPIO.LOW)os.system('echo "FAN TURNED OFF "|festival --tts')
```

我不需要为此解释相同的事情，对吧？正如您所猜到的，将其保存为`fanoff.py`。

好了！当所有这些都完成后，然后输入以下命令来检查软件是否正确安装：

```py
voicecommand -c 
```

树莓派响应唤醒词`pi`；让我们将其更改为`jarvis`。可以在打开配置文件后使用以下命令进行所有这些更改：

```py
voicecommand -e. 
```

在该文件中，输入您自己的命令。在这里，让我们添加以下代码：

```py
LIGHT_ON

LIGHT_OFF

FAN_ON

FAN_OFF
```

现在对于每个命令，定义动作。动作将是运行包含打开或关闭灯光和风扇的代码的 Python 文件。代码基本且简单易懂。将以下内容添加到文件中：

```py
LIGHT ON = sudo python lighton.py

LIGHT OFF = sudo python lightoff.py

FAN ON = sudo python fanon.py

FAN OFF = sudo python fanoff.py
```

现在，让我们看看我们做了什么。每当你说“贾维斯，开灯”，它会将你的语速转换成文本，将其与相应的程序进行比较，并执行程序中的操作。因此，在这个程序中，每当我们说“开灯”，灯就会亮起，其他命令也是类似。记得让它听到你说的话。你必须说“贾维斯”这个词，这样它才会听从命令并准备倾听。

# 总结

在这一章中，我们了解了如何与贾维斯互动，并根据我们的需求让它工作。如果这一章是关于口头交流，那么下一章将是关于手势识别，利用先进的电容技术，你将能够通过挥手来控制你的自动化系统。


# 第二十八章：手势识别

自人类诞生以来，人们就使用手势相互交流，甚至在没有任何正式语言之前。手势是交流的主要方式，这也可以从世界各地发现的古代雕塑中看出，手势一直是一种非常有效地传递大量数据的成功方式，有时甚至比语言本身更有效。

手势是自然的，它们可能是对某种情况的反射。即使在我们不知道的情况下，它也会在潜意识中发生。因此，它成为了与各种设备进行交流的理想方式。然而，问题仍然存在，如何？

我们可以肯定，如果我们谈论手势，那么我们肯定需要做大量的编程来识别视频中的手势；此外，这也需要大量的处理能力来实现。因此，这是不可能的。我们可以使用一系列接近传感器构建一些基本的手势识别系统。然而，识别的手势范围将非常有限，使用的端口也会多倍增加。

因此，我们需要找到一个易于使用且成本不会超过其提供的解决方案。

本章将涵盖以下主题：

+   电场感应

+   使用 Flick HAT

+   基于手势识别的自动化

# 电场感应

近场传感是一个非常有趣的传感领域。准备好一些有趣的东西。如果你感到有点困倦，或者注意力不集中，那就喝点咖啡，因为这个系统的工作原理可能会有点新。

每当有电荷时，就会伴随着一个相关的电场。这些电荷在空间中传播并绕过物体。当这种情况发生时，与之相关的电场具有特定的特征。只要周围的环境是空的，这种特征就会保持不变。

对于我们使用的手势识别板，它周围的感应范围只有几厘米，所以超出这一点的任何东西都可以忽略不计。如果那个区域没有任何东西，那么我们可以安全地假设被感应到的电场模式不会改变。然而，每当一个物体，比如我们的手，靠近时，这些波就会被扭曲。这种扭曲直接与物体的位置和姿势有关。通过这种扭曲，我们可以感应到手指的位置，并通过持续的感应，看到正在执行的动作是什么。所讨论的板看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/73e2e142-b4a4-4f4c-aced-19fc2353a0b1.jpg)

板上的中央交叉区域是发射器，两侧是四个矩形结构。这些是感应元件。它们感应空间中的波纹模式。基于此，它们可以推导出物体的 x、y 和 z 坐标。这由一个名为 MGC 3130 的芯片提供动力。这个芯片进行所有计算，并将原始读数传递给用户，关于坐标。

# 使用 Flick HAT

Flick HAT 以盾牌的形式出现，你可以简单地将其插入树莓派并开始使用。然而，一旦你这样做了，你就不会剩下任何 GPIO 引脚。因此，为了避免这个问题，我们将使用公对母导线连接它。这将使我们可以访问其他 GPIO 引脚，然后我们可以玩得开心。

所以，继续按以下方式连接。以下是 Flick 板的引脚图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/1685e1fc-657c-43f0-b058-708de0c1e97d.png)

然后，按照以下方式进行连接：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/80ba5ee5-864a-4132-96b9-eaca317eb73e.png)

连接完成后，只需上传这个代码，看看会发生什么：

```py
import signal
import flicklib
import time
def message(value):
   print value
@flicklib.move()
def move(x, y, z):
   global xyztxt
   xyztxt = '{:5.3f} {:5.3f} {:5.3f}'.format(x,y,z)
@flicklib.flick()
def flick(start,finish):
   global flicktxt
   flicktxt = 'FLICK-' + start[0].upper() + finish[0].upper()
   message(flicktxt)
def main():
   global xyztxt
   global flicktxt
   xyztxt = ''
   flicktxt = ''
   flickcount = 0
   while True:

  xyztxt = ''
  if len(flicktxt) > 0 and flickcount < 5:
      flickcount += 1
  else:
      flicktxt = ''
      flickcount = 0
main()
```

现在一旦你上传了代码，让我们继续了解这个代码实际在做什么。

我们正在使用一个名为`import flicklib`的库，这是由这块板的制造商提供的。这个库的函数将在本章中用于与挥动板通信和获取数据。

```py
def message(value):
    print value
```

在这里，我们定义了一个名为`message(value)`的函数，它将简单地打印传递给函数的任何值：

```py
@flicklib.move()
```

这有一个特殊的装饰器概念。根据定义，装饰器是一个接受另一个函数并扩展后者行为的函数，而不明确修改它。在上一行代码中，我们声明它是一个装饰器`@`。

这有一个特殊的作用：动态定义程序中的任何函数。这意味着用这种方法定义的函数可以根据用户的定义而有不同的工作方式。

函数`move()`将进一步由在其后定义的函数补充。这种函数称为嵌套函数。也就是函数内部的函数：

```py
def move(x, y, z):
    global xyztxt
    xyztxt = '{:5.3f} {:5.3f} {:5.3f}'.format(x,y,z)
```

在这里，我们定义了一个名为`move()`的函数，它的参数是`x`、`y`和`z`。在函数内部，我们定义了一个名为`xyztxt`的全局变量；现在，`xyztxt`的值将以五位数字的形式呈现，小数点后有三位。我们是如何知道的呢？正如你所看到的，我们使用了一个名为`format()`的函数。这个函数的作用是根据用户的要求格式化给定变量的值。我们在这里声明值为`{:5.3f}`。`:5`表示它将是五位数，`3f`表示小数点后将是三位数。因此，格式将是`xxx.xx`：

```py
def flick(start,finish):
    global flicktxt
    flicktxt = 'FLICK-' + start[0].upper() + finish[0].upper()
    message(flicktxt)
```

在这里，我们定义了一个名为`flick(start, finish)`的函数。它有两个参数：`start`和`finish`。使用行`flicktxt = 'FLICK-' + start[0].upper() + finish[0].upper()`，这是根据手势板识别的字符进行切片。如果检测到南-北挥动，则开始为南，结束为北。现在我们只使用单词的第一个字符：

```py
    global xyztxt
    global flicktxt
```

我们再次全局定义了名为`xyztxt`和`flicktxt`的变量。之前，我们所做的是在函数中定义它。因此，重要的是在主程序中定义它：

```py
if len(flicktxt) > 0 and flickcount < 5:
            flickcount += 1
else:
            flicktxt = ''
            flickcount = 0
```

当检测到手势时，`flicktxt`变量将获得与手势相对应的值。如果没有手势，那么`flicktxt`将保持为空。一个名为`flickcount`的变量将计算它被刷过多少次。如果值超出指定范围，那么`flicktxt`将使用行`flicktxt = ''`清除为空字符串，`flickcount`将被设为 0。

这将产生一个文本输出，向用户提供手势挥动的方向。

# 基于手势识别的自动化

现在我们已经按照以下图表接口了连接：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/f11065c7-a56f-4673-a5e8-9604941953e7.png)

让我们继续上传以下代码：

```py
import signal
import flicklib
import time
import RPi.GPIO as GPIO
GIPO.setmode(GPIO.BCM)
GPIO.setup(light, GPIO.OUT)
GPIO.setup(fan,GPIO.OUT)
pwm = GPIO.PWM(fan,100)
def message(value):
   print value
@flicklib.move()
def move(x, y, z):
   global xyztxt
   xyztxt = '{:5.3f} {:5.3f} {:5.3f}'.format(x,y,z)
@flicklib.flick()
def flick(start,finish):
   global flicktxt
   flicktxt = 'FLICK-' + start[0].upper() + finish[0].upper()
   message(flicktxt)
def main():
   global xyztxt
   global flicktxt
   xyztxt = ''
   flicktxt = ''
   flickcount = 0
   dc_inc = 0
   dc_dec = 0

while True:
  pwm.start(0)
  xyztxt = ' '
  if len(flicktxt) > 0 and flickcount < 5:
    flickcount += 1
  else:
    flicktxt = ''

flickcount = 0
if flicktxt ==”FLICK-WE”:
  GPIO.output(light,GPIO.LOW)
if flicktxt ==”FLICK-EW”:
  GPIO.output(light,GPIO.HIGH)
if flicktxt ==”FLICK-SN”:
  if dc_inc < 100:
    dc_inc = dc_inc + 10
    pwm.changeDutyCycle(dc_inc)

else:
  Dc_inc = 10
  if flicktxt ==”FLICK-NS”:
    if dc_inc >0:
    dc_dec = dc_dec - 10
    pwm.changeDutyCycle(dc_dec)
main()
```

该程序是在我们之前完成的程序的基础上，我们始终有一些额外的功能，可以使用通过手势板接收到的数据来开启或关闭灯光。

与之前的程序一样，我们正在以手势板上的方向形式接收手势，并使用简单的条件来关闭灯光或打开它们。因此，让我们看看有哪些添加：

```py
 if flicktxt ==”FLICK-WE”: GPIO.output(light,GPIO.LOW)
```

第一个条件很简单。我们正在将`flicktxt`的值与给定变量进行比较，在我们的情况下是`FLICK-WE`，其中`WE`代表从**西**到**东**。因此，当我们从西向东挥动，或者换句话说，当我们从左向右挥动时，灯光将被关闭：

```py
 if flicktxt ==”FLICK-EW”: GPIO.output(light,GPIO.HIGH)
```

与之前一样，我们再次使用名为`FLICK-EW`的变量，它代表从东到西的挥动。它的作用是，每当我们从东向西挥动手，或者从右向左挥动手时，灯光将被打开：

```py
 if flicktxt ==”FLICK-SN”: if dc_inc <= 100:  dc_inc = dc_inc + 20
 pwm.changeDutyCycle(dc_inc)
```

现在我们已经加入了一个调光器和一个风扇来控制风扇的速度；因此，我们将不得不给它一个与我们想要驱动它的速度相对应的 PWM。现在每当用户将手从南向北或从下到上甩动时。条件 `if dc_inc <100` 将检查 `dc_inc` 的值是否小于或等于 `100`。如果是，则它将增加 `20` 的值。使用函数 `ChangeDutyCycle()`，我们为调光器提供不同的占空比；因此改变了风扇的整体速度。每次你向上划动风扇的值，它将增加 20%：

```py
 else: Dc_inc = 10 if flicktxt ==”FLICK-NS”: if dc_inc >0:  dc_dec = dc_dec - 10
 pwm.changeDutyCycle(dc_dec)
```

# 摘要

在本章中，我们能够理解手势识别是如何通过电场检测工作的概念。我们也了解到使用手势控制板和手势控制家庭是多么容易。我们将在下一章中涵盖机器学习部分。


# 第二十九章：机器学习

从原始时代到现在，机器人和计算机都被编程来执行一系列活动。这些活动可能非常庞大。因此，为了开发复杂的程序，需要大量的软件工程师，他们日夜工作以实现某种功能。当问题定义明确时，这是可行的。但是当问题也变得非常复杂时呢？

学习是使我们成为人类的东西。我们的经验使我们能够以更好和更有效的方式适应各种情况。每次我们做某事，我们都会学到更多。这使我们在一段时间内更擅长做这项任务。俗话说熟能生巧，通过一遍又一遍地做事情来学习，使我们变得更好。

然而，让我们退一步来定义学习是什么？我想引用 Google 的说法，根据它的说法，*学习是通过学习、经验或教导获得的知识*。因此，学习基本上是一种从我们周围获取信息以理解过程及其性质的方式。

现在，你可能会想，等一下，在之前的章节中，当我们制作守卫机器人时，我们已经让我们的系统学习了很多视觉数据。你的想法是完全正确的。然而，学习可以通过不同的方式进行。对一个问题有效的方法对另一种问题可能是无效的。因此，有各种类型的学习算法和原则。在本章中，我们将专注于一种名为**k 最近邻**的算法。它被称为**懒惰算法**。我个人喜欢这个算法用于分类。为什么？因为从技术上讲，它没有训练阶段。怎么做？

k 最近邻实际上是一个聪明的算法。它不是计算所提供数据的回归并进行大量的数学计算，而是简单地从提供的数据集中获取结构化数据。每当有新的数据输入进行预测时，它只是根据用户提供的数据在数据库中搜索最接近的*k*匹配数据，基于其给定的分类。因此，在本章中，我们将学习这个算法将如何工作，以及我们如何使用它来使我们的家变得智能。

在本章中，我们将涵盖以下主题：

+   制作数据集

+   使用数据集进行预测

+   让你的家学习

+   家庭学习和自动化

# 制作数据集

现在，我们需要制作一个虚拟数据集，以便机器学习算法可以根据该数据预测应该做什么。

要制作数据集，我们需要了解正在考虑的数据是什么。在本章中，我们将基于时间和温度制作一个机器学习算法，以预测风扇应该开启还是关闭。因此，我们至少需要向系统提供两样东西，一样是“温度”，另一样是“时间”，以便进行预测。但要记住的一件事是，我们正在谈论一个监督学习算法，因此为了训练模型，我们还需要将“温度”和“时间”的结果提供给风扇的状态。在这里，风扇的状态可以是开启或关闭。因此，我们可以用`0`或`1`来表示。现在让我们继续自己制作一个数据集。

现在，要制作数据集，你只需打开 Microsoft Excel 并开始编写数据集如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/d136c76b-b6e8-462f-bb2a-69702c1da791.png)

最好拥有超过 20 组数据的数据集。此外，数据具有明显的特征并且不是随机数据是很重要的。例如，在前面的案例中，你可以看到在温度为`28`时，时间为`12.44`时，风扇将开启；然而，在同一时间，当时间为`12.13`且温度为`21`时，风扇是关闭的。

创建数据集后，您必须以 CSV 格式将其保存为名为`dataset`的文件。可能有一些用户不使用 Microsoft Excel，在这种情况下，您可以在文本编辑器中以相同格式编写数据，最后以 CSV 格式保存。

一旦您有了`dataset.csv`文件，那么您必须继续将它们复制到您将保存即将到来的代码的地方。完成后，我们可以继续下一步。

请记住，数据的质量越好，学习过程就越好。因此，您可能需要花一些时间来精心制作数据集，以便它确实有意义。

# 使用数据集进行预测

不多说了，让我们看看以下代码：

```py
import numpy as np
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier

knn = KNeighborsClassifier(n_neighbors=5)
data = pd.read_csv('dataset.csv')

x = np.array(data[['Time', 'Temp']])
y = np.array(data[['State']]).ravel()

knn.fit(x,y)

time = raw_input("Enter time")
temp = raw_input("Enter temp")

data =. []

data.append(float(time))
data.append(float(temp))

a = knn.predict([data])

print(a[0])}
```

所以，让我们看看我们在这里做了什么：

```py
import numpy as np
```

我们将`numpy`导入到我们的程序中；这有助于我们处理列表和矩阵：

```py
import pandas as pd
```

在这里，我们正在导入一个名为`pandas`的库；这有助于我们读取逗号分隔值或者叫 CSV 文件。我们将使用 CSV 文件来存储我们的数据并访问它进行学习过程：

```py
from sklearn.neighbors import KNeighborsClassifier
```

在这里，我们从`sklearn`库中导入`KneighborsClassifier`。`sklearn`本身是一个庞大的库；因此，我们只导入其中的一部分，因为在这个程序中我们不会使用全部内容：

```py
knn = KNeighborsClassifier(n_neighbors=5)
```

在这里，我们正在给变量`knn`赋值，其中值将是`KNeighborsClassifer(n_neighbors =5)`；这意味着它正在使用`KneighborsClassifer()`函数，并将参数设置为`n_neighbors=5`。这个参数告诉`KneighborsClassifer`函数算法中将有五个邻居。进一步使用这个声明，整个函数可以使用`knn`来调用：

```py
data = pd.read_csv('dataset.csv')
```

在这里，我们为名为`data`的变量提供值，传递的值是`pd.read_csv('dataset.csv')`；这意味着每当调用`data`时，将调用`pandas`库中的`pd.read_csv()`函数。这个函数的目的是从 CSV 文件中读取数据。在这里，传递的参数是`dataset.csv`；因此，它指示函数将从一个名为`dataset.csv`的文件中读取数据：

```py
x = np.array(data[['Time', 'Temp']])
```

在下一行中，我们为变量`x`传递值，传递的值是`np.array(data[['Time, 'Temp']])`。现在，`np.array`函数通过`numpy`库创建一个数组。这个数组将存储名为`Time`和`Temp`的数据：

```py
y = np.array(data[['State']]).ravel()
```

就像上一次一样，我们将`State`存储在通过`numpy`库的`.ravel()`函数创建的数组中，最后会转置数组。这样做是为了使两个数组`x`和`y`之间可以进行数学运算：

```py
knn.fit(x,y)
```

在这一小行中，我们使用了`knn`库中的`fit()`函数，它的作用是使用`x`作为主要数据，`y`作为输出结果数据来拟合模型：

```py
time = raw_input("Enter time")
temp = raw_input("Enter temp")
```

在这一行中，我们正在向用户请求数据。在第一行，我们将打印`输入时间`，然后等待用户输入时间。用户输入时间后，它将被存储在名为`time`的变量中。一旦完成，它将继续下一行；代码将打印`输入温度`，一旦提示用户输入温度，它将等待数据被收集。一旦用户收集到数据，它将把数据存储在名为`temp`的变量中：

```py
data =. []
```

在这里，我们正在创建一个名为`data`的空列表；这个列表将用于计算输出的结果状态。由于所有的机器学习算法都是以列表数据类型工作的。因此，决策的输入必须以列表的形式给出：

```py
data.append(float(time))
data.append(float(temp))
```

在这里，我们正在向我们刚刚创建的名为`data`的列表中添加数据。首先添加`time`，然后是`temp`：

```py
a = knn.predict([data])
```

完成后，将使用`knn`算法中的名为`predict`的函数来根据提供的名为`data`的列表来预测输出。预测算法的输出将被提取到一个名为`a`的变量中：

```py
print(a[0])
```

最后，一旦预测完成，我们将读取`a`的值，并记住所有的数据 I/O 都是以列表的形式进行的。因此，预测算法给出的数据输出也将以列表格式呈现。因此，我们打印列表的第一个元素。

此输出将根据用户提供的数据集预测风扇的状态。因此，继续输入温度和时间，让系统为您预测结果。看看它是否正常工作。如果不正常，那么尝试向 CSV 文件添加更多数据集，或者查看数据集中的值是否真的有意义。我相信您最终会得到一个出色的预测系统。

# 让您的家学习

一旦这个构想完成了，继续将其连接起来，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/b6b1a2eb-d4ae-4138-a36c-2feb1b73e5cc.png)

设置好之后，是时候将以下代码写入我们的树莓派了：

```py
import Adafruit_DHT
import datetime
import RPi.GPIO as GPIO
import time
import numpy as np
import pandas as pd
import Adafruit_DHT
from sklearn.neighbors import KNeighborsClassifier

GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)

fan = 22
light = 23
sw1 = 13
sw2 = 14

GPIO.setup(led1,GPIO.OUT)
GPIO.setup(led2,GPIO.OUT)
GPIO.setup(sw1,GPIO.IN)
GPIO.setup(sw2,GPIO.IN)

sensor = 11
pin = 2

f = open("dataset.csv","a+")
count = 0
while count < 50:

 data = ""

 H = datetime.datetime.now().strftime('%H')
 M = datetime.datetime.now().strftime('%M')

 data = str(H)+"."+str(M)
 humidity,temperature = Adafruit_DHT.read_retry(sensor,pin)
 data = data + "," + str(temperature)

prev_state = state

 if (GPIO.input(sw1) == 0) and (GPIO.input(sw2) == 0):
     state = 0
     GPIO.output(light,GPIO.LOW)
     GPIO.output(fan,GPIO.LOW)

 elif (GPIO.input(sw1) == 0) and (GPIO.input(sw2) == 1):
     state = 1
     GPIO.output(light,GPIO.HIGH)
     GPIO.output(fan,GPIO.LOW)

 elif (GPIO.input(sw1) == 1) and (GPIO.input(sw2) == 0):
    state = 2
     GPIO.output(light,GPIO.LOW)
     GPIO.output(fan,GPIO.HIGH)

 elif (GPIO.input(sw1) == 1) and (GPIO.input(sw2) == 1):
    state = 3
     GPIO.output(light,GPIO.HIGH)
     GPIO.output(fan,GPIO.HIGH)

 data = ","+str(state)

if prev_state =! state:

     f.write(data)
     count = count+1

f.close()
```

现在，让我们看看我们在这里做了什么：

```py
f = open("dataset.csv","a+")
```

在这行代码中，我们将值`open("dataset.csv", "a+")`赋给变量`f`。然后，`open()`函数将打开传递给它的文件，我们的情况下是`dataset.csv`；参数`a+`表示将值附加到 CSV 文件的末尾。因此，这行代码将打开文件`dataset.csv`并添加我们稍后将传递的值：

```py
 data = ""
```

我们通过名称`data`声明了一个空字符串：

```py
 data = str(H)+"."+str(M)
```

我们正在将小时和分钟的值添加到字符串中，用点号分隔以进行区分。因此，数据看起来像`HH.MM`：

```py
 humidity,temperature = Adafruit_DHT.read_retry(sensor,pin)
```

我们使用这行代码从 DHT 11 传感器读取湿度和温度读数，并将这些值传递给变量`humidity`和`temperature`：

```py
data = data + "," + str(temperature)
```

一旦数据被读取，我们也将温度添加到变量`data`中。因此，现在数据看起来像这样`HH.MM`和`TT.TT`：

```py
 if (GPIO.input(sw1) == 0) and (GPIO.input(sw2) == 0):
 state = 0
 elif (GPIO.input(sw1) == 0) and (GPIO.input(sw2) == 1):
 state = 1
 elif (GPIO.input(sw1) == 1) and (GPIO.input(sw2) == 0):
 state = 2
 elif (GPIO.input(sw1) == 1) and (GPIO.input(sw2) == 1):
 state = 3
```

在这里，我们定义了不同类型的状态，这些状态对应于开关组合。其表格如下：

| **开关 1** | **开关 2** | **状态** |
| --- | --- | --- |
| `0` | `0` | `0` |
| `0` | `1` | `1` |
| `1` | `0` | `2` |
| `1` | `1` | `3` |

因此，通过状态的值，我们可以了解哪个开关将被打开，哪个将被关闭：

```py
 data = ","+str(state)
```

最后，状态的值也被添加到名为`data`的变量中。现在，最终，数据看起来像`HH.MM`，`TT.TT`和`S`：

```py
f.write(data)
```

现在，使用`write()`函数，我们正在将数据的值写入到我们之前定义的文件中，该文件的值为`f`。

因此，每次开关打开或关闭时，数据都将被收集，并且该值将以时间戳记录在文件中。这些数据随后可以用于在任何给定时间预测家庭的状态，而无需任何干预：

```py
if prev_state =! state:

     f.write(data)
     count = count+1
```

在这里，我们正在将状态与`prev_state`进行比较，您可以在我们的程序中看到。先前的状态是在程序开始时计算的。因此，如果系统的状态发生任何变化，那么`prev_state`和`state`的值将不同。这将导致`if`语句为真。当发生这种情况时，数据将使用`write()`函数写入到我们的文件中。传递的参数是需要写入的值。最后，计数的值增加了`1`。

一旦这个程序运行了几个小时或者可能是几天，它将收集关于灯光和风扇开关模式的一些非常有用的数据。此后，这些数据可以被获取到之前的程序中，程序将能够根据时间和温度做出自己的决定。

# 家庭学习和自动化

现在，在前面的部分中，我们已经了解了学习的工作原理，现在是时候利用这个概念制作一个能够自动理解我们的功能并做出决策的机器人了。基于我们的决定，系统将判断应该做什么。但这一次，而不是由用户提供一组数据，让这个程序自己创建数据。一旦数据对自己的功能似乎足够，那么，不用太多的解释，让我们直接开始吧：

```py
import Adafruit_DHT
import datetime
import RPi.GPIO as GPIO
import time
import numpy as np
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier

GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)

light = 22
fan = 23
sw1 = 13
sw2 = 14

GPIO.setup(light,GPIO.OUT)
GPIO.setup(fan,GPIO.OUT)
GPIO.setup(sw1,GPIO.IN)
GPIO.setup(sw2,GPIO.IN)

sensor = 11
pin = 2

f = open("dataset.csv","a+")
count = 0

while count < 200:

        data = ""

        H = datetime.datetime.now().strftime('%H')
        M = datetime.datetime.now().strftime('%M')

        data = str(H)+"."+str(M)
        humidity,temperature = Adafruit_DHT.read_retry(sensor,pin)
        data = data + "," + str(temperature)

prev_state = state

 if (GPIO.input(sw1) == 0) and (GPIO.input(sw2) == 0):
     state = 0
     GPIO.output(light,GPIO.LOW)
     GPIO.output(fan,GPIO.LOW)

 elif (GPIO.input(sw1) == 0) and (GPIO.input(sw2) == 1):
     state = 1
     GPIO.output(light,GPIO.HIGH)
     GPIO.output(fan,GPIO.LOW)

 elif (GPIO.input(sw1) == 1) and (GPIO.input(sw2) == 0):
    state = 2
     GPIO.output(light,GPIO.LOW)
     GPIO.output(fan,GPIO.HIGH)

 elif (GPIO.input(sw1) == 1) and (GPIO.input(sw2) == 1):
    state = 3
     GPIO.output(light,GPIO.HIGH)
     GPIO.output(fan,GPIO.HIGH)

 data = ","+str(state)

 if prev_state =! state:

     f.write(data)
     count = count+1

Test_set = []
knn = KNeighborsClassifier(n_neighbors=5)
data = pd.read_csv('dataset.csv')

X = np.array(data[['Time', 'Temp']])
y = np.array(data[['State']]).ravel()

knn.fit(X,y)

While Count > 200:

    time = ""

    H = datetime.datetime.now().strftime('%H')
    M = datetime.datetime.now().strftime('%M')

    time = float(str(H)+"."+str(M))

    humidity, temperature = Adafruit_DHT.read_retry(sensor, pin)

 temp = int(temperature)
 test_set.append(time)
 test_set.append(temp)

 a = knn.predict([test_set]])
 Out = a[0]

 If out == 0:
 GPIO.output(light,GPIO.LOW)
 GPIO.output(fan,GPIO.LOW)

 If out == 1:
 GPIO.output(light,GPIO.LOW)
 GPIO.output(fan,GPIO.HIGH)

 If out == 2:
 GPIO.output(light,GPIO.HIGH)
 GPIO.output(fan,GPIO.LOW)

 If out == 3:
 GPIO.output(light,GPIO.HIGH)
 GPIO.output(fan,GPIO.HIGH)

```

现在让我们看看我们在这里做了什么。在这个程序中，条件`while count < 200:`内的程序的第一部分与我们在上一个代码中所做的完全相同。所以，它只是根据用户的要求做事情，同时，它正在从用户那里获取值以了解他们的工作行为：

```py
while count > 200:
```

此后，当计数超过`200`时，代码的第二部分将开始执行，这是在前面的循环内部：

```py
    time = ""
```

在这一行中，我们正在形成一个名为 time 的空字符串，我们将在其中存储时间的值：

```py
    H = datetime.datetime.now().strftime('%H')
    M = datetime.datetime.now().strftime('%M')
```

我们将时间的值存储到名为`H`和`M`的变量中：

```py
    time = float(str(H)+"."+str(M))
```

我们现在将时间的值存储在字符串`time`中。这将包括小时和分钟：

```py
 temp = int(temperature)
```

为了简化计算并减少系统的计算负载，我们正在减小温度变量的大小。我们通过去掉小数位来做到这一点。为了做到这一点`TT.TT`，我们只是消除小数点并将其转换为整数。这是通过名为`int()`的函数完成的。温度的整数值将存储在名为`temp`的变量中：

```py
 test_set.append(time)
 test_set.append(temp)
```

在这里，我们将时间和温度的值添加到名为`test_set`的列表中，如果您查看程序，那么您将看到程序中间声明了一个空集。所以，现在这个`test_set`有了`time`和`temp`的值，这可以进一步被预测算法用来预测状态：

```py
 a = knn.predict([test_set]])
```

使用名为`predict()`的简单函数从`knn`函数中，我们可以预测状态的值。我们只需要将数据或`test_set`列表传递给预测函数。这个函数的输出将是一个存储在变量`a`中的列表：

```py
 Out = a[0]
```

`Out`的值将设置为列表`a`的第一个元素：

```py
 If out == 0:
 GPIO.output(light,GPIO.LOW)
 GPIO.output(fan,GPIO.LOW)

 If out == 1:
 GPIO.output(light,GPIO.LOW)
 GPIO.output(fan,GPIO.HIGH)

 If out == 2:
 GPIO.output(light,GPIO.HIGH)
 GPIO.output(fan,GPIO.LOW)

 If out == 3:
 GPIO.output(light,GPIO.HIGH)
 GPIO.output(fan,GPIO.HIGH)
```

使用前面的代码块，我们能够根据算法预测的状态有选择地打开灯和风扇。因此，使用这个，程序将能够自动预测并打开或关闭灯和风扇，无需您的干预。

# 总结

在本章中，我们了解了即使没有学习，机器学习是如何工作的。我们了解了如何提供数据集，并且可以使用现有系统创建新的数据集。最后，我们了解了系统如何无缝地收集数据，从数据中学习，最终提供输入。
