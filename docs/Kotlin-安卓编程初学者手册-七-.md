# Kotlin 安卓编程初学者手册（七）

> 原文：[`zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A`](https://zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二十二章：粒子系统和处理屏幕触摸

我们已经在上一章中使用线程实现了我们的实时系统。在本章中，我们将创建将存在并在这个实时系统中演变的实体，就像它们有自己的思想一样。

我们还将学习用户如何通过学习如何设置与屏幕交互的能力来将这些实体绘制到屏幕上。这与在 UI 布局中与小部件交互是不同的。

以下是本章的内容：

+   向屏幕添加自定义按钮

+   编写`Particle`类的代码

+   编写`ParticleSystem`类的代码

+   处理屏幕触摸

我们将首先向我们的应用程序添加自定义 UI。

# 向屏幕添加自定义按钮

我们需要让用户控制何时开始另一个绘图并清除屏幕上的先前工作。我们还需要让用户能够决定何时将绘图带到生活中。为了实现这一点，我们将在屏幕上添加两个按钮，分别用于这些任务。

在`LiveDrawingView`类的其他属性之后，将以下新属性添加到代码中：

```kt
// These will be used to make simple buttons
private var resetButton: RectF
private var togglePauseButton: RectF
```

我们现在有两个`RectF`实例。这些对象每个都包含四个`Float`坐标，每个按钮的每个角都有一个坐标。

我们现在将向`LiveDrawingView`类添加一个`init`块，并在首次创建`LiveDrawingView`实例时初始化位置，如下所示：

```kt
init {
   // Initialize the two buttons
   resetButton = RectF(0f, 0f, 100f, 100f)
   togglePauseButton = RectF(0f, 150f, 100f, 250f)
}
```

现在我们已经为按钮添加了实际坐标。如果你在屏幕上可视化这些坐标，你会看到它们在左上角，暂停按钮就在重置/清除按钮的下方。

现在我们可以绘制按钮。将以下两行代码添加到`LiveDrawingView`类的`draw`函数中。现有的注释准确显示了新突出显示的代码应该放在哪里：

```kt
// Draw the buttons
canvas.drawRect(resetButton, paint)
canvas.drawRect(togglePauseButton, paint)

```

新代码使用了`drawRect`函数的重写版本，我们只需将我们的两个`RectF`实例直接传递给通常的`Paint`实例。我们的按钮现在将出现在屏幕上。

我们将在本章后面看到用户如何与这些略显粗糙的按钮交互。

# 实现粒子系统效果

粒子系统是控制粒子的系统。在我们的情况下，`ParticleSystem`是一个我们将编写的类，它将产生`Particle`类的实例（许多实例），这些实例将一起创建一个简单的爆炸效果。

这是一些由粒子系统控制的粒子的屏幕截图，可能在本章结束时出现：

![实现粒子系统效果](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_22_05.jpg)

为了澄清，每个彩色方块都是`Particle`类的一个实例，所有`Particle`实例都由`ParticleSystem`类控制和持有。此外，用户将通过用手指绘制来创建多个（数百个）`ParticleSystem`实例。粒子系统将出现为点或块，直到用户点击暂停按钮并使其活动起来。我们将仔细检查代码，以便您能够在代码中修改`Particle`和`ParticleSystem`实例的大小、颜色、速度和数量。

### 注意

读者可以将额外的按钮添加到屏幕上，以允许用户更改这些属性作为应用程序的功能。

我们将首先编写`Particle`类的代码。

## 编写`Particle`类的代码

添加`import`语句，成员变量，构造函数和以下代码中显示的`init`块：

```kt
import android.graphics.PointF

class Particle(direction: PointF) {

    private val velocity: PointF = PointF()
    val position: PointF = PointF()

    init {
          // Determine the direction
          velocity.x = direction.x
          velocity.y = direction.y
    }
```

我们有两个属性——一个用于速度，一个用于位置。它们都是`PointF`对象。`PointF`保存两个`Float`值。粒子的位置很简单：它只是一个水平和垂直值。速度值值得解释一下。`velocity`对象`PointF`中的两个值将是速度，一个是水平的，另一个是垂直的。这两个速度的组合将产生一个方向。

接下来，添加以下`update`函数；我们稍后将更详细地查看它：

```kt
fun update() {
    // Move the particle
    position.x += velocity.x
    position.y += velocity.y
}
```

每个`Particle`实例的`update`函数将由`ParticleSystem`对象的`update`函数在应用程序的每一帧中调用，而`ParticleSystem`对象的`update`函数将由`LiveDrawingView`类（再次在`update`函数中）调用，我们将在本章后面编写。

在`update`函数中，`position`的水平和垂直值将使用`velocity`的相应值进行更新。

### 提示

请注意，我们在更新中没有使用当前的帧速率。如果您想确保您的粒子以确切的速度飞行，您可以修改这一点，但所有的速度都将是随机的。添加这个额外的计算并没有太多好处（对于每个粒子）。然而，正如我们很快会看到的，`ParticleSystem`类需要考虑每秒的帧数来测量它应该运行多长时间。

现在我们可以继续进行`ParticleSystem`类的学习。

## 编写 ParticleSystem 类

`ParticleSystem`类比`Particle`类有更多的细节，但仍然相当简单。记住我们需要用这个类来实现的功能：持有、生成、更新和绘制一堆（相当大的一堆）`Particle`实例。

添加以下构造函数、属性和导入语句：

```kt
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.PointF

import java.util.*

class ParticleSystem {

    private var duration: Float = 0f
    private var particles: 
         ArrayList<Particle> = ArrayList()

    private val random = Random()
    var isRunning = false
```

我们有四个属性：首先是一个名为`duration`的`Float`，它将被初始化为我们希望效果运行的秒数；名为`particles`的`ArrayList`实例，它持有`Particle`实例，并将保存我们为该系统实例化的所有`Particle`对象。

创建名为`random`的`Random`实例，因为我们需要生成如此多的随机值，每次创建一个新对象都会使我们的速度变慢一点。

最后，名为`isRunning`的`Boolean`将跟踪粒子系统当前是否正在显示（更新和绘制）。

现在我们可以编写`initParticles`函数。每当我们想要一个新的`ParticleSystem`时，将调用此函数。请注意，唯一的参数是一个名为`numParticles`的`Int`。

当我们调用`initParticles`时，我们可以有一些乐趣来初始化大量的粒子。添加以下`initParticles`函数，然后我们将更仔细地查看代码：

```kt
fun initParticles(numParticles:Int){

   // Create the particles
   for (i in 0 until numParticles) {
         var angle: Double = random.nextInt(360).toDouble()
         angle *= (3.14 / 180)

         // Option 1 - Slow particles
         val speed = random.nextFloat() / 3

         // Option 2 - Fast particles
         //val speed = (random.nextInt(10)+1);

         val direction: PointF

         direction = PointF(Math.cos(
                     angle).toFloat() * speed,
                     Math.sin(angle).toFloat() * speed)

         particles.add(Particle(direction))

    }
}
```

`initParticles`函数只包括一个`for`循环来完成所有工作。`for`循环从零到`numParticles`运行。

首先生成介于 0 和 359 之间的随机数，并将其存储在`Float angle`中。接下来，有一点数学运算，我们将`angle`乘以`3.14/180`。这将角度从度转换为弧度制的度量，这是`Math`类所需的度量单位，我们稍后将在其中使用。

然后，我们生成另一个介于 1 和 10 之间的随机数，并将结果分配给名为`speed`的`Float`变量。

### 注意

请注意，我已经添加了注释，以建议代码中的不同值选项。我在`ParticleSystem`类的几个地方都这样做了，当我们到达章节的末尾时，我们将有一些乐趣改变这些值，并看看这对绘图应用程序的影响。

现在我们有了一个随机角度和速度，我们可以将它们转换并组合成一个向量，这个向量可以在每一帧的`update`函数中使用。

### 注意

向量是一个确定方向和速度的值。我们的向量存储在`direction`对象中，直到传递到`Particle`构造函数中。向量可以有许多维度。我们的向量由两个维度组成，因此定义了 0 到 359 度之间的方向和 1 到 10 之间的速度。您可以在我的网站上阅读更多关于向量、方向、正弦和余弦的内容：[`gamecodeschool.com/essentials/calculating-heading-in-2d-games-using-trigonometric-functions-part-1/`](http://gamecodeschool.com/essentials/calculating-heading-in-2d-games-using-trigonometric-functions-part-1/)。

我决定不解释使用`Math.sin`和`Math.cos`创建向量的单行代码，因为其中的魔法部分发生在以下公式中：

+   角度 x`速度`的余弦

+   角度 x`速度`的正弦

其余的魔法发生在`Math`类提供的余弦和正弦函数的隐藏计算中。如果您想了解它们的全部细节，可以查看前面的提示。

最后，创建一个新的`Particle`，然后将其添加到`particles ArrayList`中。

接下来，我们将编写`update`函数。请注意，`update`函数需要当前的帧速率作为参数。编写`update`函数如下：

```kt
fun update(fps: Long) {
   duration -= 1f / fps

   for (p in particles) {
         p.update()
  }

   if (duration < 0) {
         isRunning = false
  }
}
```

`update`函数内部的第一件事是从`duration`中减去经过的时间。请记住，`fps`表示每秒帧数，因此`1/fps`给出的是秒的一小部分值。

接下来是一个`for`循环，它为`particles`中的每个`Particle`实例调用`update`函数。

最后，代码检查粒子效果是否已经完成，如果是，则将`isRunning`设置为`false`。

现在我们可以编写`emitParticles`函数，该函数将使每个`Particle`实例运行，不要与`initParticles`混淆，后者创建所有新粒子并赋予它们速度。`initParticles`函数将在用户开始与屏幕交互之前调用一次，而`emitParticles`函数将在每次效果需要启动时调用，用户在屏幕上绘制时。

使用以下代码添加`emitParticles`函数：

```kt
fun emitParticles(startPosition: PointF) {
    isRunning = true

    // Option 1 - System lasts for half a minute
    duration = 30f

    // Option 2 - System lasts for 2 seconds
    //duration = 3f

    for (p in particles) {
          p.position.x = startPosition.x
          p.position.y = startPosition.y
   }
}
```

首先，注意将`PointF`作为参数传递，所有粒子将从同一位置开始，然后根据它们各自的随机速度在每一帧上扩散。

`isRunning`布尔值设置为`true`，`duration`设置为`30f`，因此效果将持续 30 秒，`for`循环将将每个粒子的位置设置为起始坐标。

我们的`ParticleSysytem`的最终函数是`draw`函数，它将展示效果的全部荣耀。该函数接收对`Canvas`和`Paint`的引用，以便可以绘制到`LiveDrawingView`刚刚在其`draw`函数中锁定的相同`Canvas`实例上。

添加如下的`draw`函数：

```kt
fun draw(canvas: Canvas, paint: Paint) {

    for (p in particles) {

           // Option 1 - Colored particles
           //paint.setARGB(255, random.nextInt(256),
           //random.nextInt(256),
           //random.nextInt(256))

           // Option 2 - White particles
           paint.color = Color.argb(255, 255, 255, 255)
           // How big is each particle?

           // Option 1 - Big particles
           //val sizeX = 25f
           //val sizeY = 25f

           // Option 2 - Medium particles
           //val sizeX = 10f
           //val sizeY = 10f

           // Option 3 - Tiny particles
           val sizeX = 12f
           val sizeY = 12f

           // Draw the particle
           // Option 1 - Square particles
           canvas.drawRect(p.position.x, p.position.y,
                       p.position.x + sizeX,
                       p.position.y + sizeY,
                       paint)

          // Option 2 - Circular particles
          //canvas.drawCircle(p.position.x, p.position.y,
          //sizeX, paint)
   }
}
```

在前面的代码中，`for`循环遍历`particles`中的每个`Particle`实例。然后使用`drawRect`绘制每个`Particle`。

### 注意

再次注意，我建议不同的代码更改选项，这样我们在完成编码后可以有些乐趣。

我们现在可以开始让粒子系统工作了。

## 在`LiveDrawingView`类中生成粒子系统

添加一个充满系统的`ArrayList`实例和一些其他成员来跟踪事物。在现有注释所指示的位置添加以下突出显示的代码：

```kt
// The particle systems will be declared here later
private val particleSystems = ArrayList<ParticleSystem>()

private var nextSystem = 0
private val maxSystems = 1000
private val particlesPerSystem = 100

```

现在我们可以跟踪多达 1,000 个每个系统中有 100 个粒子的粒子系统。随意调整这些数字。在现代设备上，您可以运行数百万个粒子而不会遇到任何问题，但在模拟器上，当粒子数量达到几十万个时，它将开始出现问题。

通过添加以下突出显示的代码在`init`块中初始化系统：

```kt
init {

  // Initialize the two buttons
  resetButton = RectF(0f, 0f, 100f, 100f)
  togglePauseButton = RectF(0f, 150f, 100f, 250f)

  // Initialize the particles and their systems
  for (i in 0 until maxSystems) {
 particleSystems.add(ParticleSystem())
 particleSystems[i]
 .initParticles(particlesPerSystem)
 }
}
```

代码循环遍历`ArrayList`，对每个`ParticleSystem`实例调用构造函数，然后调用`initParticles`。

现在我们可以通过将突出显示的代码添加到`update`函数中，在循环的每一帧中更新系统：

```kt
private fun update() {
  // Update the particles
  for (i in 0 until particleSystems.size) {
 if (particleSystems[i].isRunning) {
 particleSystems[i].update(fps)
         }
 }
}
```

前面的代码循环遍历每个`ParticleSystem`实例，首先检查它们是否活动，然后调用`update`函数并传入当前的每秒帧数。

现在我们可以通过在`draw`函数中添加以下片段中的突出显示代码来在循环的每一帧中绘制系统：

```kt
// Choose the font size
paint.textSize = fontSize.toFloat()

// Draw the particle systems
for (i in 0 until nextSystem) {
 particleSystems[i].draw(canvas, paint)
}

// Draw the buttons
canvas.drawRect(resetButton, paint)
canvas.drawRect(togglePauseButton, paint)
```

先前的代码循环遍历`particleSystems`，对每个调用`draw`函数。当然，我们实际上还没有生成任何实例；为此，我们需要学习如何响应屏幕交互。

# 处理触摸

要开始屏幕交互，将`OnTouchEvent`函数添加到`LiveDrawingView`类中，如下所示：

```kt
override fun onTouchEvent(
   motionEvent: MotionEvent): Boolean {

   return true
}
```

这是一个被覆盖的函数，并且每当用户与屏幕交互时，Android 都会调用它。看看`onTouchEvent`的唯一参数。

事实证明，`motionEvent`中隐藏了大量数据，这些数据包含了刚刚发生的触摸的详细信息。操作系统将其发送给我们，因为它知道我们可能需要其中的一些数据。

请注意，我说的是*其中一部分*。`MotionEvent`类非常庞大；它包含了几十个函数和属性。

目前，我们只需要知道屏幕会在玩家的手指移动、触摸屏幕或移开手指的精确时刻做出响应。

我们将使用`motionEvent`中包含的一些变量和函数，包括以下内容：

+   `action`属性，不出所料，保存了执行的动作。不幸的是，它以稍微编码的格式提供了这些信息，这就解释了其他一些变量的必要性。

+   `ACTION_MASK`变量提供了一个称为掩码的值，再加上一点 Kotlin 技巧，可以用来过滤`action`中的数据。

+   `ACTION_UP`变量，我们可以用它来判断执行的动作（例如移开手指）是否是我们想要响应的动作。

+   `ACTION_DOWN`变量，我们可以用它来判断执行的动作是否是我们想要响应的动作。

+   `ACTION_MOVE`变量，我们可以用它来判断执行的动作是否是移动/拖动动作。

+   `x`属性保存事件发生的水平浮点坐标。

+   `y`属性保存事件发生的垂直浮点坐标。

举个具体的例子，假设我们需要使用`ACTION_MASK`过滤`action`中的数据，并查看结果是否与`ACTION_UP`相同。如果是，那么我们知道用户刚刚从屏幕上移开了手指，也许是因为他们刚刚点击了一个按钮。一旦我们确定事件是正确类型的，我们就需要使用`x`和`y`找出事件发生的位置。

还有一个最后的复杂情况。我提到的 Kotlin 技巧是`&`位运算符，不要与我们一直与`if`关键字一起使用的逻辑`&&`运算符混淆。

`&`位运算符用于检查两个值中的每个对应部分是否为真。这是在使用`ACTION_MASK`和`action`时所需的过滤器。

### 注意

理智检查：我不愿详细介绍`MotionEvent`和位运算。完全可以完成整本书的编写，甚至制作出专业质量的交互式应用，而无需完全理解它们。如果你知道我们将在下一节中编写的代码行确定了玩家触发的事件类型，那么这就是你需要知道的全部。我只是认为像你这样有洞察力的读者可能想了解系统的方方面面。总之，如果你理解位运算，那太好了；你可以继续。如果你不理解，也没关系；你仍然可以继续。如果你对位运算感兴趣（有很多），你可以在[`en.wikipedia.org/wiki/Bitwise_operation`](https://en.wikipedia.org/wiki/Bitwise_operation)上阅读更多关于它们的内容。

现在我们可以编写`onTouchEvent`函数，并查看所有`MotionEvent`的相关内容。

## 编写`onTouchEvent`函数

通过在`onTouchEvent`函数中添加以下片段中的突出显示代码来响应用户在屏幕上移动手指：

```kt
// User moved a finger while touching screen
if (motionEvent.action and MotionEvent.
 ACTION_MASK == 
 MotionEvent.ACTION_MOVE) {

 particleSystems[nextSystem].emitParticles(
 PointF(motionEvent.x,
 motionEvent.y))

 nextSystem++
 if (nextSystem == maxSystems) {
 nextSystem = 0
 }
}

return true
```

`if`条件检查是否事件类型是用户移动手指。如果是，则调用`particleSystems`中的下一个粒子系统的`emitParticles`函数。然后，增加`nextSystem`变量，并进行测试，看它是否是最后一个粒子系统。如果是，则将`nextSystem`设置为零，准备在下次需要时重新使用现有的粒子系统。

我们可以继续让系统响应用户按下按钮，通过在下面的片段中添加高亮显示的代码，紧接着我们刚刚讨论过的代码之后，在我们已经编码的`return`语句之前：

```kt
// Did the user touch the screen
if (motionEvent.action and MotionEvent.ACTION_MASK ==
 MotionEvent.ACTION_DOWN) {

 // User pressed the screen so let's 
 // see if it was in the reset button
 if (resetButton.contains(motionEvent.x,
 motionEvent.y)) {

 // Clear the screen of all particles
 nextSystem = 0
 }

 // User pressed the screen so let's 
 // see if it was in the toggle button
 if (togglePauseButton.contains(motionEvent.x,
 motionEvent.y)) {

 paused = !paused
 }
}

return true
```

`if`语句的条件检查是否用户已经点击了屏幕。如果是，则`RectF`类的`contains`函数与`x`和`y`一起使用，以查看该按压是否在我们的自定义按钮之一内。如果按下了重置按钮，则当`nextSystem`设置为零时，所有粒子将消失。如果按下了暂停按钮，则切换`paused`的值，导致在线程内停止/开始调用`update`函数。

## 完成 HUD

编辑`printDebuggingText`函数中的代码，使其显示如下：

```kt
canvas.drawText("Systems: $nextSystem",
         10f, (fontMargin + debugStart + 
         debugSize * 2).toFloat(), paint)

canvas.drawText("Particles: ${nextSystem * 
         particlesPerSystem}",
         10f, (fontMargin + debugStart 
         + debugSize * 3).toFloat(), paint)
```

前面的代码将在屏幕上打印一些有趣的统计数据，告诉我们当前正在绘制多少粒子和系统。

# 运行应用程序

现在我们可以看到实时绘图应用程序的运行情况，并尝试一些我们在代码中留下注释的不同选项。

以小、圆、多彩、快速的粒子运行应用程序。下面的屏幕截图显示了屏幕上已经被点击了几次：

![运行应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_22_01.jpg)

然后恢复绘图，如下面的屏幕截图所示：

![运行应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_22_03.jpg)

制作一个儿童风格的绘图，粒子小、白色、方形、缓慢、持续时间长，如下面的屏幕截图所示：

![运行应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_22_02.jpg)

然后恢复绘图，并等待 20 秒，让绘图活跃起来并发生变化：

![运行应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_22_04.jpg)

# 摘要

在本章中，我们学习了如何将成千上万个独立的实体添加到我们的实时系统中。这些实体由`ParticleSystem`类控制，而`ParticleSystem`类又与游戏循环进行交互和控制。由于游戏循环在一个线程中运行，我们了解到用户仍然可以无缝地与屏幕进行交互，操作系统将通过`onTouchEvent`函数向我们发送这些交互的详细信息。

在下一章中，当我们探索如何播放音效时，我们的应用程序最终会变得有些喧闹。


# 第二十三章：Android 声音效果和 Spinner 小部件

在本章中，我们将学习`SoundPool`类以及我们可以根据是否只想播放声音或进一步跟踪我们正在播放的声音的不同方式。然后，我们将把我们学到的一切付诸实践，制作一个很酷的声音演示应用程序，这也将向我们介绍一个新的 UI 小部件：**spinner**。

在本章中，我们将做以下事情：

+   学习如何使用 Android 的`SoundPool`类

+   使用`SpinnerView`编写基于声音的应用程序

让我们开始吧。

# SoundPool 类

`SoundPool`类允许我们持有和操作一组声音效果：字面上就是一组声音。该类处理从解压缩声音文件（如`.wav`或`.ogg`文件）到通过整数 ID 保持标识引用，以及当然，播放声音的一切。当声音播放时，它以非阻塞的方式播放（在后台使用线程），不会干扰我们应用程序的流畅运行或用户与应用程序的交互。

我们需要做的第一件事是将声音效果添加到游戏项目的`main`文件夹中名为`assets`的文件夹中。我们很快就会做到这一点。

接下来，在我们的 Kotlin 代码中，我们声明了`SoundPool`类型的对象和每个我们打算使用的声音效果的`Int`标识符，如下面的代码所示。我们还将声明另一个名为`nowPlaying`的`Int`，我们可以用它来跟踪当前正在播放的声音；我们很快就会看到我们如何做到这一点：

```kt
var sp: SoundPool
var idFX1 = -1
nowPlaying = -1
volume = .1f
```

现在，我们将看一下初始化`SoundPool`的方式。

## 初始化 SoundPool

我们将使用`AudioAttributes`对象来设置我们想要的声音池的属性。

第一个代码块使用链接，并在一个对象上调用了四个单独的函数，初始化了我们的`AudioAttributes`对象（`audioAttributes`），如下面的代码所示：

```kt
val audioAttributes = AudioAttributes.Builder()
         .setUsage(AudioAttributes.
                     USAGE_ASSISTANCE_SONIFICATION)
         .setContentType(AudioAttributes.
                     CONTENT_TYPE_SONIFICATION)
         .build()

sp = SoundPool.Builder()
         .setMaxStreams(5)
         .setAudioAttributes(audioAttributes)
         .build()
```

在上面的代码中，我们使用了此类的`Builder`函数来初始化一个`AudioAttributes`实例，让它知道它将用于`USAGE_ASSISTANCE_SONIFICATION`的用户界面交互。

我们还使用了`CONTENT_TYPE_SONIFICATION`，让该类知道它是用于响应声音，例如按钮点击，碰撞或类似的声音。

现在，我们可以通过传入`AudioAttributes`对象（`audioAttributes`）和我们可能想要播放的同时声音的最大数量来初始化`SoundPool`（`sp`）本身。

第二个代码块将另外四个函数链接到`sp`的初始化中，包括调用`setAudioAttributes`，该函数使用我们在前面链接函数块中初始化的`audioAttributes`对象。

现在，我们可以继续加载（解压缩）声音文件到我们的`SoundPool`中。

### 将声音文件加载到内存中

与我们的线程控制一样，我们需要将我们的代码包装在`try`-`catch`块中。这是有道理的，因为读取文件可能因我们无法控制的原因而失败，但我们也这样做是因为我们被迫这样做，因为我们使用的函数会抛出异常，否则我们编写的代码将无法编译。

在`try`块内，我们声明并初始化了`AssetManager`和`AssetFileDescriptor`类型的对象。

`AssetFileDescriptor`是通过使用`AssetManager`对象的`openFd`函数来初始化的，该函数解压缩声音文件。然后，我们初始化我们的 ID（`idFX1`），同时将`AssetFileDescriptor`实例的内容加载到我们的`SoundPool`中。

`catch`块只是简单地在控制台输出一条消息，让我们知道是否出了问题，如下面的代码所示：

```kt
try {
    // Create objects of the 2 required classes
    val assetManager = this.assets
    var descriptor: AssetFileDescriptor

    // Load our fx in memory ready for use
    descriptor = assetManager.openFd("fx1.ogg")
    idFX1 = sp.load(descriptor, 0)

}  catch (e: IOException) {
    // Print an error message to the console
    Log.e("error", "failed to load sound files")
}
```

现在，我们准备制造一些噪音。

### 播放声音

此时，我们的`SoundPool`中有一个音效，并且我们有一个 ID 可以用来引用它。

这是我们播放声音的方式。请注意，在下面的代码行中，我们使用相同的函数的返回值初始化`nowPlaying`变量。因此，以下代码同时播放声音并将正在播放的 ID 的值加载到`nowPlaying`中：

```kt
nowPlaying = sp.play(idFX2,
  volume, volume, 0, repeats, 1f)
```

### 提示

不需要将 ID 存储在`nowPlaying`中以播放声音，但是它有其用途，我们现在将看到。

`play`函数的参数从左到右如下：

+   声音效果的 ID

+   左右扬声器音量

+   可能正在播放/已播放的其他声音的优先级

+   声音重复的次数

+   播放速率/速度（1 为正常速率）

在我们制作声音演示应用程序之前，还有一件事情需要讨论。

### 停止声音

当仍在播放时，使用`stop`函数停止声音也非常容易，如下面的代码所示。请注意，可能会有多个音效在任何给定时间播放，因此`stop`函数需要您想要停止的音效的 ID：

```kt
sp.stop(nowPlaying)
```

当您调用`play`时，如果您想要跟踪它以便以后与它交互，您只需要存储当前播放声音的 ID。现在，我们可以制作声音演示应用程序。

# 声音演示应用程序介绍 Spinner 小部件

当然，谈到音效，我们需要一些实际的声音文件。您可以使用 BFXR 制作自己的声音文件（如下一节所述）或使用提供的声音文件。该应用程序的音效包含在下载包中，并且可以在`Chapter23/Sound Demo`文件夹的`assets`文件夹中找到。

## 制作音效

有一个名为 BFXR 的开源应用程序，允许我们制作自己的音效。以下是使用 BFXR 制作自己的音效的快速指南。从[www.bfxr.net](http://www.bfxr.net)免费获取一份副本。

### 提示

请注意，声音演示应用程序的音效包含在`Chapter23/assets`文件夹中。除非您愿意，否则您不必创建自己的音效，但是学习如何使用它仍然是值得的。

按照网站上的简单说明进行设置。尝试一些这样的事情来制作酷炫的音效：

### 提示

这是一个非常简化的教程。您可以使用 BFXR 做很多事情。要了解更多，请阅读我们之前提到的网站上的提示。

1.  运行`bfxr`。您应该会看到一个类似于下面屏幕截图所示的屏幕：![制作音效](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_23_04.jpg)

1.  尝试所有生成该类型随机声音的预设类型，如下面的屏幕截图所示。当您有一个接近您想要的声音时，继续下一步：![制作音效](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_23_05.jpg)

1.  使用滑块微调音高、持续时间和其他方面的新声音，如下面的屏幕截图所示：![制作音效](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_23_06.jpg)

1.  通过单击**导出 Wav**按钮保存您的声音，如下面的屏幕截图所示。尽管这个按钮的文本，正如我们将看到的，我们也可以保存为`.wav`以外的格式：![制作音效](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_23_07.jpg)

1.  Android 与 OGG 格式的声音非常兼容，因此在要求命名文件时，请在文件名的末尾使用`.ogg`扩展名。

1.  重复步骤 2 到 5 以创建三个酷炫的音效。将它们命名为`fx1.ogg`，`fx2.ogg`和`fx3.ogg`。我们使用`.ogg`文件格式，因为它比 WAV 等格式更压缩。

当您的声音文件准备好后，我们可以继续进行应用程序。

## 布置声音演示 UI

我将比之前的项目更简要地描述我们正在适应的项目的部分。但是，每当有新概念时，我一定会详细解释。我想现在您应该可以轻松地将一些小部件拖放到`ConstraintLayout`上并更改它们的`text`属性。

完成以下步骤，如果遇到任何问题，您可以复制或查看下载包的`Chapter23/Sound Demo`文件夹中的代码：

1.  创建一个新项目，称其为`Sound Demo`，选择**基本活动**，并在**最低 API 级别**选项上选择**API 21：Android 5.0（棒棒糖）**，但将所有其他设置保持默认，并删除**Hello world!** `TextView`。

1.  按照从上到下，然后从左到右的顺序，从**容器**类别中拖动一个**下拉列表**，从**小部件**类别中拖动一个**SeekBar** **（离散）**，并从调色板上拖动四个**按钮**到布局上，同时排列和调整它们的大小，并设置它们的`text`属性，如下图所示：![布局声音演示 UI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_23_01.jpg)

1.  点击**推断约束**按钮。

1.  使用以下表格设置它们的属性：

| Widget | 要更改的属性 | 要设置的值 |
| --- | --- | --- |
| Spinner | id | `spinner` |
| 下拉列表 | spinnerMode | `dropdown` |
| Spinner | 条目 | `@array/spinner_options` |
| SeekBar | id | `seekBar` |
| SeekBar | max | `10` |
| 按钮（**FX 1**） | id | `btnFX1` |
| 按钮（**FX 2**） | id | `btnFX2` |
| 按钮（**FX 3**） | id | `btnFX3` |
| 按钮（**STOP**） | id | `btnStop` |

1.  接下来，将以下突出显示的代码添加到`values`文件夹中的`strings.xml`文件中。我们在上一步中使用了这个名为`spinner_options`的字符串资源数组，用于`options`属性。它将代表可以从我们的下拉列表中选择的选项：

```kt
   <resources>
       <string name="app_name">Sound Demo</string>

       <string name="hello_world">Hello world!</string>
       <string name="action_settings">Settings</string>

       <string-array name="spinner_options">
         <item>0</item>
         <item>1</item>
         <item>3</item>
         <item>5</item>
         <item>10</item>
       </string-array>

    </resources>
```

现在运行应用程序，最初你不会看到任何之前没有看到的东西。但是，如果你点击下拉列表，你将看到我们称为`spinner_options`的字符串数组中的选项。我们将使用下拉列表来控制播放时音效重复的次数，如下图所示：

![布局声音演示 UI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_23_02.jpg)

让我们编写 Kotlin 代码，使这个应用程序工作，包括我们如何与我们的下拉列表交互。

使用您操作系统的文件浏览器，转到项目的`app\src\main`文件夹，并添加一个名为`assets`的新文件夹。

在下载包的`Chapter23/Sound Demo/assets`文件夹中为您准备了三个音频文件。将这三个文件放入您刚创建的`assets`目录中，或者使用您自己创建的文件。重要的是它们的文件名必须是`fx1.ogg`，`fx2.ogg`和`fx3.ogg`。

## 编写声音演示

首先，我们将更改类声明，以便我们可以高效地处理所有小部件的交互。编辑声明以实现`View.OnClickListener`，如下面的代码中所突出显示的那样：

```kt
class MainActivity : AppCompatActivity(), 
  View.OnClickListener {
```

我们将很快添加所需的`onClick`函数。

现在，我们将为我们的`SoundPool`实例、音效 ID 和`nowPlaying Int`属性添加一些属性，正如我们之前讨论的，我们还将添加一个`Float`来保存设备当前音量基础上的 0（静音）到 1（最大音量）之间的音量值。我们还将添加一个名为`repeats`的`Int`属性，它意料之中地保存我们将重复给定音效的次数的值：

```kt
var sp: SoundPool   

private var idFX1 = -1
private var idFX2 = -1
private var idFX3 = -1

var nowPlaying = -1
var volume = .1f
var repeats = 2

init{

  val audioAttributes = AudioAttributes.Builder()
        .setUsage(AudioAttributes.
              USAGE_ASSISTANCE_SONIFICATION)
        .setContentType(AudioAttributes.
              CONTENT_TYPE_SONIFICATION)
        .build()

  sp = SoundPool.Builder()
        .setMaxStreams(5)
        .setAudioAttributes(audioAttributes)
        .build()
}
```

在前面的代码中，我们还添加了一个`init`块，我们在其中初始化了我们的`SoundPool`实例。

### 提示

使用您喜欢的方法添加以下`import`语句，以使前面的代码工作：

```kt
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.SoundPool
import android.os.Build

import android.view.View
import android.widget.Button
```

现在，在`onCreate`函数中，我们可以像往常一样为我们的按钮设置点击监听器，如下所示：

```kt
btnFX1.setOnClickListener(this)
btnFX2.setOnClickListener(this)
btnFX3.setOnClickListener(this)
btnStop.setOnClickListener(this)
```

### 提示

确保添加以下`import`以使前面的代码工作：

```kt
import kotlinx.android.synthetic.main.content_main.*
```

接下来，我们依次加载我们的每个音效，并用与我们加载到`SoundPool`中的相关音效匹配的值初始化我们的 ID。整个过程都包裹在`try`-`catch`块中，如下面的代码所示，根据需要：

```kt
try {
    // Create objects of the 2 required classes
    val assetManager = this.assets
    var descriptor: AssetFileDescriptor

    // Load our fx in memory ready for use
    descriptor = assetManager.openFd("fx1.ogg")
    idFX1 = sp.load(descriptor, 0)

    descriptor = assetManager.openFd("fx2.ogg")
    idFX2 = sp.load(descriptor, 0)

    descriptor = assetManager.openFd("fx3.ogg")
    idFX3 = sp.load(descriptor, 0)

}   catch (e: IOException) {
    // Print an error message to the console
    Log.e("error", "failed to load sound files")
}
```

### 提示

使用您喜欢的方法添加以下`import`语句，以使前面的代码工作：

```kt
import android.content.res.AssetFileDescriptor
import android.content.res.AssetManager
import android.util.Log
import java.io.IOException
```

接下来，我们将看看如何处理`SeekBar`。正如您可能已经期待的那样，我们将使用 lambda。我们将使用`OnSeekBarChangeListener`并重写`onProgressChanged`、`onStartTrackingTouch`和`onStopTrackingTouch`函数。

我们只需要向`onProgressChanged`函数添加代码。在这个函数中，我们只需更改`volume`变量的值，然后在我们的`SoundPool`对象上使用`setVolume`函数，传入当前播放的声音效果以及左右声道的音量，如下面的代码所示：

```kt
seekBar.setOnSeekBarChangeListener(
         object : SeekBar.OnSeekBarChangeListener {

   override fun onProgressChanged(
         seekBar: SeekBar, value: Int, fromUser: Boolean) {

         volume = value / 10f
         sp.setVolume(nowPlaying, volume, volume)
  }

   override fun onStartTrackingTouch(seekBar: SeekBar) {}

   override fun onStopTrackingTouch(seekBar: SeekBar) {

  }
})
```

### 提示

使用您喜欢的方法为先前的代码添加以下`import`语句：

```kt
import android.widget.SeekBar
```

`SeekBar`之后是`Spinner`和另一个处理用户交互的 lambda。我们将使用`AdapterView.OnItemSelectedListener`来重写`onItemSelected`和`onNothingSelected`函数。

我们所有的代码都放在`onItemSelected`函数中，它创建了一个临时的名为`temp`的`String`，然后使用`Integer.ValueOf`函数将`String`转换为`Int`，我们可以用它来初始化`repeats`属性，如下面的代码所示：

```kt
 spinner.onItemSelectedListener =
         object : AdapterView.OnItemSelectedListener {

   override fun onItemSelected(
         parentView: AdapterView<*>,
         selectedItemView: View,
         position: Int, id: Long) {

         val temp = spinner.selectedItem.toString()
         repeats = Integer.valueOf(temp)
  }

   override fun onNothingSelected(
         parentView: AdapterView<*>) {
  }
}
```

### 提示

使用您喜欢的方法将以下`import`语句添加到先前的代码中：

```kt
import android.widget.AdapterView
import android.widget.Spinner
```

这就是`onCreate`函数的所有内容。

现在，实现`onClick`函数，这是必需的，因为这个类实现了`View.OnClickListener`接口。非常简单，每个按钮都有一个`when`选项。请注意，对`play`的每次调用的返回值都存储在`nowPlaying`中。当用户按下**STOP**按钮时，我们只需使用`nowPlaying`的当前值调用`stop`，导致最近启动的声音效果停止，如下面的代码所示：

```kt
 override fun onClick(v: View) {
   when (v.id) {
         R.id.btnFX1 -> {
               sp.stop(nowPlaying)
               nowPlaying = sp.play(idFX1, volume,
                           volume, 0, repeats, 1f)
    }

         R.id.btnFX2 -> {
               sp.stop(nowPlaying)
               nowPlaying = sp.play(idFX2,
                           volume, volume, 0, repeats, 1f)
    }

         R.id.btnFX3 -> {
               sp.stop(nowPlaying)
               nowPlaying = sp.play(idFX3,
                           volume, volume, 0, repeats, 1f)
    }

         R.id.btnStop -> sp.stop(nowPlaying)
   }
}
```

现在我们可以运行应用程序。如果听不到任何声音，请确保设备的音量已调高。

单击适当的按钮以播放所需的声音效果。更改音量和重复播放次数，当然，尝试使用**STOP**按钮停止它。

还要注意，当一个声音效果正在播放时，您可以重复点击多个播放按钮，声音将同时播放，直到我们设置的最大流数（五）。

# 总结

在本章中，我们仔细研究了如何使用`SoundPool`，并利用了所有这些知识来完成声音演示应用程序。

在下一章中，我们将学习如何使我们的应用程序与多个不同的布局配合工作。


# 第二十四章：设计模式、多个布局和片段

我们已经走了很长的路，从最开始设置 Android Studio 的时候。那时，我们一步一步地进行了一切，但随着我们的进展，我们试图向你展示的不仅仅是如何将*x*添加到*y*或将特性 A 添加到应用程序 B，而是让你能够以自己的方式使用所学的知识，以便将自己的想法变为现实。

这一章更加关注你未来的应用程序，而不是这本书中迄今为止的任何其他章节。我们将看一下 Kotlin 和 Android 的一些特性，你可以将其用作框架或模板，以制作更加令人兴奋和复杂的应用程序，同时保持代码的可管理性。此外，我将建议进一步学习的领域，这些领域在本书中几乎没有涉及，因为它的范围有限。

在本章中，我们将学习以下内容：

+   模式和模型-视图-控制器

+   Android 设计指南

+   开始真实世界设计和处理多个不同设备

+   片段简介

让我们开始吧。

# 介绍模型-视图-控制器模式

**短语模型、视图**和**控制器**反映了我们应用程序的不同部分分为不同的部分，称为**层**。Android 应用程序通常使用模型-视图-控制器**模式**。模式只是一种公认的结构代码和其他应用程序资源的方式，例如布局文件、图像和数据库。

模式对我们很有用，因为通过遵循模式，我们可以更有信心地做正确的事情，并且不太可能因为将自己编码到尴尬的境地而不得不撤销大量的辛苦工作。

计算机科学中有许多模式，但只要理解 MVC 模式就足以创建一些专业构建的 Android 应用程序。

我们已经部分使用了 MVC，所以让我们依次看看这三个层。

## 模型

模型指的是驱动我们应用程序的数据以及专门管理它并使其可用于其他层的逻辑/代码。例如，在我们的自我备忘录应用程序中，`Note`类及其 JSON 代码就是数据和逻辑。

## 视图

自我备忘录应用程序的视图是所有不同布局中的所有小部件。用户在屏幕上可以看到或与之交互的任何内容通常都是视图的一部分。你可能还记得小部件来自 Android API 的`View`类层次结构。

## 控制器

控制器是视图和模型之间的部分。它与两者交互并使它们分开。它包含所谓的**应用逻辑**。如果用户点击按钮，应用程序层决定如何处理它。当用户点击**确定**以添加新的备忘录时，应用程序层会监听视图层上的交互。它捕获视图中包含的数据，并将其传递给模型层。

### 提示

设计模式是一个庞大的主题。有许多不同的设计模式，如果你想对这个主题有一个友好的入门，我会推荐*Head First Design Patterns*。即使这本书的例子是用另一种语言 Java 描述的，它对你仍然非常有用。如果你想真正深入设计模式的世界，那么你可以尝试*Design Patterns: Elements of Reusable Object-Oriented Software*，它被认为是一种设计模式的权威，但阅读起来要困难得多。

随着本书的进展，我们还将开始利用我们已经讨论过但迄今为止尚未充分利用的面向对象编程特性。我们将逐步做到这一点。

# Android 设计指南

应用程序设计是一个广阔的主题——如此广阔，以至于只能在专门致力于该主题的书中开始教授。而且，就像编程一样，只有通过不断的练习、复习和改进，才能开始擅长应用程序设计。

那么，我所说的设计到底是什么？我说的是屏幕上放置小部件的位置，使用哪些小部件，它们应该是什么颜色，多大，如何在屏幕之间过渡，滚动页面的最佳方式，何时以及使用哪些动画插值器，你的应用应该分成哪些屏幕，以及更多其他方面。

这本书希望能让你有能力*实现*你选择的答案，以及更多其他问题的答案。不幸的是，它没有足够的空间，作者可能也没有技能来教你如何*做出*这些选择。

### 提示

你可能会想，“我该怎么办？”继续制作应用，不要让缺乏设计经验和知识阻止你！甚至将你的应用发布到应用商店。然而，请记住，还有一个完全不同的话题——设计——如果你的应用真的要成为世界级的话，这需要一些关注。

即使在中等规模的开发公司中，设计师很少也是程序员，即使是非常小的公司也经常外包他们的应用设计（或设计师可能外包编码）。

设计既是一门艺术，也是一门科学，Google 已经证明它认识到这一点，为现有和有抱负的设计师提供了高质量的支持。

### 提示

我强烈建议你访问并收藏网页[`developer.android.com/design/`](https://developer.android.com/design/)。它非常详细和全面，完全专注于 Android，并提供了大量的数字资源，如图像、调色板和指南。

将理解设计原则作为短期目标。将提高你的实际设计技能作为一个持续的任务。访问并阅读以设计为重点的网站，并尝试实现你发现令人兴奋的想法。

然而，最重要的是，不要等到你成为设计专家才开始制作应用。继续将你的想法付诸实践并发布它们。要求每个应用的设计都比上一个稍微好一点。

我们将在接下来的章节中看到，而且已经在一定程度上看到，Android API 为我们提供了一整套超时尚的 UI，我们可以用非常少的代码或设计技能来利用这些 UI。这些 UI 在很大程度上使你的应用看起来像是由专业人员设计的。

# 真实世界的应用

到目前为止，我们已经构建了十几个或更多不同复杂度的应用。大多数是在手机上设计和测试的。

当然，在现实世界中，我们的应用需要在任何设备上都能良好运行，并且必须能够处理在横向或纵向视图（在所有设备上）时发生的情况。

此外，我们的应用通常不能只是在不同设备上正常工作并看起来“还行”。通常情况下，我们的应用需要根据设备是手机、平板还是横向/纵向方向，以不同的方式运行并呈现出显著不同的 UI。

### 注意

Android 支持大屏电视、智能手表、虚拟和增强现实以及物联网的应用。本书不涉及后两个方面，但作者希望在书的结尾，你将有足够的准备去涉足这些话题。

看一下 BBC 新闻应用在 Android 手机上纵向运行的屏幕截图。看基本布局，但也注意新闻的类别（**头条新闻**，**世界**，**英国**）都是可见的，并允许用户滚动查看更多类别或在每个类别的故事之间左右滑动：

![真实世界的应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_01.jpg)

我们将在下一章中看到如何使用`ImagePager`和`FragmentPager`类实现滑动/分页 UI，但在此之前，我们需要了解更多的基础知识，我们将在本章中探讨。目前，上一个截图的目的不是向您展示特定的 UI 功能，而是让您将其与以下截图进行比较。看看在平板电脑上横向方向上运行的完全相同的应用程序：

![真实世界的应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_02.jpg)

请注意，故事（数据层）是相同的，但布局（视图层）却非常不同。用户不仅可以从应用程序顶部的选项卡菜单中选择类别，还可以通过“添加主题”选项添加自己的选项卡。

再次，这张图片的重点不是向您展示特定的 UI，甚至不是我们如何实现类似的 UI，而是它们是如此不同，以至于它们很容易被误认为是完全不同的应用程序。

Android 允许我们设计真实世界的应用程序，不仅布局因设备类型/方向/大小而异，行为也是如此，即应用程序层。Android 实现这一点的秘密武器是`Fragment`类。

### 注意

**Google 说：**

“片段代表活动中的行为或用户界面的一部分。您可以在单个活动中组合多个片段，构建多窗格 UI，并在多个活动中重用片段。”

您可以将片段视为活动的模块化部分，它具有自己的生命周期，接收自己的输入事件，并且您可以在活动运行时添加或删除它（有点像可以在不同活动中重用的“子活动”）。

“片段必须始终嵌入在活动中，并且片段的生命周期直接受到宿主活动生命周期的影响。”

我们可以在不同的 XML 文件中设计多个不同的布局，并很快就会这样做。我们还可以在代码中检测设备方向和屏幕分辨率，以便我们可以动态地对布局做出决策。

让我们尝试使用设备检测，然后我们将首次查看片段。

# 设备检测迷你应用

了解检测和响应设备及其不同属性（屏幕、方向等）的最佳方法是制作一个简单的应用程序。让我们通过以下步骤来做到这一点：

1.  创建一个新的**空活动**项目，并将其命名为`设备检测`。将所有其他设置保留为默认设置。

1.  在**设计**选项卡中打开`activity_main.xml`文件，并删除默认的**Hello world!** `TextView`。

1.  将一个**按钮**拖放到屏幕顶部，并将其**onClick**属性设置为`detectDevice`。我们将在一分钟内编写此功能。

1.  将两个**TextView**小部件拖放到布局中，一个放在另一个下面，并将它们的**id**属性分别设置为`txtOrientation`和`txtResolution`。

1.  检查您是否有一个类似以下截图的布局：

### 提示

我已经拉伸了我的小部件（主要是水平方向），并将`textSize`属性增加到`24sp`，以使它们在屏幕上更清晰，但这并不是应用程序正常工作所必需的。

![设备检测迷你应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_03.jpg)

1.  单击**推断约束**按钮以确保 UI 元素的位置。

现在，我们将做一些新的事情：我们将专门为横向方向构建一个布局。

在 Android Studio 中，确保在编辑器中选择了`activity_main.xml`文件，并找到**预览方向**按钮，如下截图所示：

![设备检测迷你应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_12.jpg)

单击它，然后选择**创建横向变化**。

现在，你有一个新的布局 XML 文件，名称相同，但是是横向布局。在编辑器中，布局看起来是空白的，但正如我们将看到的那样，情况并非如此。查看项目资源管理器中的`layout`文件夹，注意确实有两个名为`activity_main`的文件，其中一个（我们刚刚创建的新文件）以**（land）**结尾。如下截图所示：

![设备检测迷你应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_09.jpg)

选择这个新文件（以**（land）**结尾的文件），现在看组件树。如下截图所示：

![设备检测迷你应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_13.jpg)

看起来布局已经包含了所有我们的小部件，只是在设计视图中看不到它们。这种异常的原因是，当我们创建横向布局时，Android Studio 复制了纵向布局，包括所有约束。纵向约束很少与横向约束匹配。

要解决这个问题，点击**删除所有约束**按钮；它是**推断约束**按钮左边的按钮。现在 UI 没有约束了。我的界面是这样的：

![设备检测迷你应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_10.jpg)

布局有点混乱，但至少我们现在可以看到它。重新排列它使其看起来整洁。这是我重新排列的方式：

![设备检测迷你应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_11.jpg)

点击**推断约束**按钮以锁定布局在新位置。

现在我们已经为两种不同方向的基本布局，我们可以把注意力转向我们的 Kotlin 代码。

## 编写 MainActivity 类

我们已经有一个调用名为`detectDevice`的函数的机制，我们只需要编写这个演示应用的函数。在`MainActivity`类的`onCreate`函数之后，添加处理按钮点击并运行检测代码的函数，如下所示：

```kt
fun detectDevice(v: View) {
   // What is the orientation?
   val display = windowManager.defaultDisplay
   txtOrientation.text = "${display.rotation}"

   // What is the resolution?
   val xy = Point()
   display.getSize(xy)
   txtResolution.text = "x = ${xy.x} y = ${xy.y}"
}
```

### 提示

导入以下三个类：

```kt
import android.graphics.Point
import android.view.Display
import android.view.View
```

这段代码通过声明和初始化一个名为`display`的`Display`类型的对象来工作。这个对象（`display`）现在包含了关于设备特定显示属性的大量数据。

存储在`rotation`属性中的值将输出到顶部的`TextView`小部件中。

然后，代码初始化了一个名为`xy`的`Point`类型的对象。`getSize`函数将屏幕分辨率加载到`xy`中。然后将结果用于将水平（`xy.x`）和垂直（`xy.y`）分辨率输出到`TextView`中。

每次点击按钮，两个`TextView`小部件都将被更新。

### 解锁屏幕方向

在运行应用之前，我们要确保设备没有被锁定在纵向模式（大多数新手机默认是这样）。从模拟器的应用抽屉（或者你将要使用的设备）中，点击**设置**应用，选择**显示**，然后使用开关将**自动旋转屏幕**设置为开启。我在下图中展示了这个设置：

![解锁屏幕方向](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_08.jpg)

## 运行应用

现在，你可以运行应用并点击按钮，如下图所示：

![运行应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_04.jpg)

使用模拟器控制面板上的旋转按钮之一将设备旋转到横向，如下截图所示：

![运行应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_14.jpg)

### 提示

你也可以在 PC 上使用*CTRL* + *F11*，或者在 macOS 设备上使用*CTRL* + *FN* + *F11*。

现在，再次点击按钮，你将看到横向布局的效果，如下图所示：

![运行应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_05.jpg)

你可能会注意到的第一件事是，当你旋转屏幕时，屏幕会短暂变空白。这是活动重新启动并再次执行`onCreate`。这正是我们需要的。它在横向布局上调用`setContentView`，`MainActivity`中的代码引用具有相同 ID 的小部件，因此完全相同的代码可以工作。

### 注意

暂时考虑一下，如果我们需要在两个方向之间需要不同的行为和布局，我们该如何处理。不要花太长时间思考这个问题，因为我们将在本章后面讨论这个问题。

如果`0`和`1`的结果对您来说不太明显，它们指的是`Surface`类的`public const`变量，其中`Surface.ROTATION_0`等于零，`Surface.ROTATION_180`等于一。

### 注意

请注意，如果您将屏幕向左旋转，那么您的值将是`1`，与我的相同，但如果您将其向右旋转，您将看到值为`3`。如果您将设备旋转到纵向模式（倒置），您将得到值`4`。

我们可以使用`when`块并根据这些检测测试的结果执行不同的代码并加载不同的布局。但正如我们刚才看到的，Android 使事情变得比这更简单，它允许我们将特定布局添加到具有配置限定符的文件夹中，比如**land**。

# 配置限定符

我们已经在第三章中看到了配置限定符，比如`layout-large`或`layout-xhdpi`，*探索 Android Studio 和项目结构*。在这里，我们将刷新并扩展对它们的理解。

我们可以通过使用配置限定符来减轻我们对控制器层的依赖，以影响应用程序布局。有关大小、方向和像素密度的配置限定符。要利用配置限定符，我们只需按照通常的方式设计一个针对我们首选配置进行优化的布局，然后将该布局放入 Android 识别为特定配置的文件夹中。

例如，在先前的应用程序中，将布局放在`land`文件夹中告诉 Android 在设备处于横向方向时使用该布局。

前面的陈述可能显得有些模糊。这是因为 Android Studio 项目资源管理器窗口显示了一个文件和文件夹结构，它并不完全对应现实——它试图简化事情并“帮助”我们。如果您从项目资源管理器窗口顶部的下拉列表中选择**项目文件**选项，然后检查项目的内容，您确实会看到有一个布局和`layout-land`文件夹，如下面的屏幕截图所示：

![配置限定符](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_15.jpg)

切换回**Android**布局或保持在**项目文件**视图上，以您喜欢的方式。

如果我们想要横向和纵向有不同的布局，我们可以在`res`文件夹中创建一个名为`layout-land`的文件夹（或者使用我们在先前应用程序中使用的快捷方式），并在其中放置我们专门设计的布局。

当设备处于纵向方向时，将使用`layout`文件夹中的常规布局，当设备处于横向方向时，将使用`layout-land`文件夹中的布局。

如果我们要为不同尺寸的屏幕设计，我们将布局放入以下名称的文件夹中：

+   `layout-small`

+   `layout-normal`

+   `layout-large`

+   `layout-xlarge`

如果我们要为不同像素密度的屏幕设计，我们可以将 XML 布局放入名称为这些的文件夹中：

+   `layout-ldpi` 用于低 DPI 设备

+   `layout-mdpi` 用于中等 DPI 设备

+   `layout-hdpi` 用于高 DPI 设备

+   `layout-xhdpi` 用于超高 DPI 设备

+   `layout-xxhdpi` 用于超超高 DPI 设备

+   `layout-xxxhdpi` 用于超超超高 DPI 设备

+   `layout-nodpi` 用于其他情况下未考虑的 DPI 设备

+   `layout-tvdpi` 用于电视

低、高或超高 DPI 等的具体资格可以在以下信息框中的链接中找到。这里要说明的是布局存储的位置。

值得一提的是，我们刚刚讨论的远远不是关于配置限定符的整个故事，就像设计一样，值得将其列入进一步学习的清单。

### 注意

正如经常发生的那样，Android 开发者网站上有大量关于处理不同设备布局的详细信息。请访问[`developer.android.com/guide/practices/screens_support`](https://developer.android.com/guide/practices/screens_support)获取更多信息。

## 配置限定符的限制

以前的应用程序和我们对配置限定符的讨论向我们展示了在许多情况下肯定非常有用。然而，不幸的是，配置限定符和在代码中检测属性只解决了我们 MVC 模式的视图层中的问题。

正如我们讨论过的，我们的应用程序有时需要具有不同的*行为*，以及布局。这可能意味着我们的 Kotlin 代码在控制器层（在我们以前的应用程序中是`MainActivity`）中可能有多个分支，并且可能召唤出对每种不同情况具体代码的巨大的`if`或`when`块的可怕愿景。

幸运的是，这并不是这样做的方式。对于这种情况——事实上，对于大多数应用程序——Android 都有**片段**。

# 片段

片段很可能会成为您制作的几乎每个应用程序的基本组成部分。它们非常有用，有很多使用它们的理由，而且一旦您习惯了它们，它们就变得非常简单，几乎没有理由不使用它们。

片段是应用程序的可重用元素，就像任何类一样，但正如我们之前提到的，它们具有特殊功能，例如能够加载自己的视图/布局，以及它们自己的生命周期函数，这使它们非常适合实现我们在真实世界应用程序部分讨论的目标。

让我们深入了解片段，一次一个特性。

## 片段也有生命周期

我们可以通过覆盖适当的生命周期函数来设置和控制片段，就像我们对活动所做的那样。

### onCreate 函数

在`onCreate`函数中，我们可以初始化变量并几乎做所有我们通常在`Activity onCreate`函数中做的事情。这个例外是初始化我们的 UI。

### onCreateView 函数

在`onCreateView`函数中，我们将像其名称所示的那样，获取对我们任何 UI 小部件的引用，设置 lambda 以监听点击，以及更多，正如我们很快将看到的那样。

### onAttach 和 onDetach 函数

`onAttach`和`onDetach`函数在`Fragment`实例被投入使用/停止使用之前调用。

### onStart，onPause 和 onStop 函数

在`onStart`，`onPause`和`onStop`函数中，我们可以执行某些操作，例如创建或删除对象或保存数据，就像我们在它们基于活动的对应函数中所做的那样。

还有其他片段生命周期函数，但我们已经了解足够开始使用片段了。如果您想学习片段生命周期的详细信息，可以在 Android 开发者网站上进行学习[`developer.android.com/guide/components/fragments`](https://developer.android.com/guide/components/fragments)。

这都很好，但我们需要一种方法来首先创建我们的片段，并配置它们以响应这些函数。

## 使用 FragmentManager 管理片段

`FragmentManager`类是`Activity`类的一部分。我们使用它来初始化`Fragment`实例，将`Fragment`实例添加到布局中，并结束`Fragment`。我们在以前的“Note to self”应用程序中初始化`FragmentDialog`实例时曾简要看到`FragmentManager`。

学习 Android 很难不碰到`Fragment`类，就像学习 Kotlin 很难不断碰到 OOP、类等一样。

以下代码片段中的突出显示的代码是提醒我们如何使用传递给弹出对话框的参数 `FragmentManager`（它已经是 `Activity` 类的一部分）：

```kt
button.setOnClickListener {
   val myDialog = MyDialog()
   myDialog.show(supportFragmentManager, "123")
   // This calls onCreateDialog
   // Don't worry about the strange looking 123
   // We will find out about this in Chapter 18
}
```

当时，我要求您不要关心函数调用的参数。调用的第二个参数是 `Fragment` 的 ID。我们很快将看到如何更广泛地使用 `FragmentManager` 和 `Fragment` ID。

`FragmentManager` 正是其名称所暗示的。这里重要的是，一个 `Activity` 只有一个 `FragmentManager`，但它可以管理多个 `Fragment` 实例。这正是我们需要的，以便在单个应用程序中具有多个行为和布局。

`FragmentManager` 还调用它负责的各个片段的各种生命周期函数。这与 `Activity` 的生命周期函数是不同的，后者是由 Android 调用的，但它也与 `FragmentManager` 密切相关，因为 `FragmentManager` 调用许多 `Fragment` 生命周期函数是作为对 `Activity` 生命周期函数的响应。通常情况下，我们不需要太担心它是何时以及如何做到这一点，只要我们在每种情况下做出适当的响应即可。

# 我们的第一个片段应用

让我们构建一个尽可能简单的片段，以便我们可以理解发生了什么，然后我们开始在各个地方生成真正有用的 `Fragment` 对象。

### 提示

我敦促所有读者去完成并构建这个项目。从一个文件跳到另一个文件，仅仅阅读说明就会使它看起来比实际复杂得多。当然，您可以从下载包中复制并粘贴代码，但也请按照步骤进行，并创建自己的项目和类。片段并不太难，但它们的实现，就像它们的名称所暗示的那样，有点分散。

使用 **Empty Activity** 模板创建一个名为 `Simple Fragment` 的新项目，并将其余设置保持默认。

请注意，有选项可以创建一个带有片段的项目，但是通过自己从头开始做事情，我们会学到更多。

切换到 `activity_main.xml` 并删除默认的 **Hello world!** `TextView`。

现在，通过在 **Component tree** 窗口中左键单击选择根 `ConstraintLayout`，然后将其 **id** 属性更改为 `fragmentHolder`。现在我们将能够在我们的 Kotlin 代码中引用此布局，并且正如 **id** 属性所暗示的那样，我们将向其中添加一个片段。

现在，我们将创建一个布局，该布局将定义我们片段的外观。右键单击 `layout` 文件夹，然后选择 **New | Layout resource file**。在 **File name:** 字段中，键入 `fragment_layout`，然后左键单击 **OK**。我们刚刚创建了一个 `LinearLayout` 类型的新布局。

在布局的任何位置添加一个单独的 **Button** 小部件，并将其 **id** 属性设置为 `button`。

现在我们有了一个供我们的片段使用的简单布局，让我们编写一些 Kotlin 代码来创建实际的片段。

请注意，您可以通过从调色板中简单地拖放一个 `Fragment` 实例来创建一个 `Fragment` 实例，但以这种方式做事情的灵活性和可控性要少得多，而灵活性和可控性是使用片段的重要好处，正如我们将在本章和接下来的三章中看到的那样。通过创建一个扩展 `Fragment` 的类，我们可以从中制作出许多片段。

在项目资源管理器中，右键单击包含 `MainActivity` 文件的文件夹。从上下文菜单中，创建一个名为 `SimpleFragment` 的新 Kotlin 类。

在我们的新 `SimpleFragment` 类中，将代码更改为继承自 `Fragment`。在输入代码时，将要求您选择要导入的特定 `Fragment` 类，如下面的屏幕截图所示：

![我们的第一个片段应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_06.jpg)

选择顶部选项（如前面的屏幕截图所示），即常规的 `Fragment` 类。

### 注意

我们将在这个类中需要以下所有的导入语句：

```kt
import android.app.Fragment
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.Toast
```

此时代码如下所示：

```kt
class SimpleFragment: Fragment() {
}
```

现在，添加一个名为`myString`的`String`属性并初始化它，如下面的代码所示：

```kt
class SimpleFragment: Fragment() {
    val myString: String = "Hello from SimpleFragment"
}
```

在使用`Fragment`时，我们需要在`onCreateView`函数中处理布局。现在让我们重写它，学习如何设置视图并获取对我们的`Button`的引用。

将以下代码添加到`SimpleFragment`类中：

```kt
override fun onCreateView(
          inflater: LayoutInflater,
          container: ViewGroup?,
          savedInstanceState: Bundle?)
          : View? {

  val view = inflater.inflate(
              R.layout.fragment_layout,
              container,
              false)  

  return view
}
```

为了理解上一段代码，我们首先必须查看`onCreateView`的签名。请注意，在第一个实例中，签名说明它必须返回一个`View`类型的对象，如下面的代码所示：

```kt
…:View?
```

接下来，我们有三个参数。让我们先看前两个：

```kt
(inflater: LayoutInflater, container: ViewGroup?...
```

我们需要一个`LayoutInflater`，因为我们不能调用`setContentView`，因为`Fragment`没有提供这样的函数。在`onCreateView`的主体中，我们使用`inflater`的`inflate`函数来膨胀我们在`fragment_layout.xml`中包含的布局，并用结果初始化`view`（`View`类型的对象）。

我们在`inflate`函数中也使用了传入`onCreateView`的`container`作为参数。`container`变量是对`activity_main.xml`中的布局的引用。

`activity_main.xml`是包含布局可能看起来很明显，但是正如我们将在本章后面看到的那样，`ViewGroup container`参数允许*任何*`Activity`与*任何*布局成为我们的 fragment 的容器。这是非常灵活的，并且在很大程度上使我们的`Fragment`代码可重用。

我们传递给`inflate`的第三个参数是`false`，这意味着我们不希望我们的布局立即添加到包含的布局中。我们很快将从代码的另一个部分自己完成这个步骤。

`onCreateView`的第三个参数是`Bundle savedInstanceState`，它可以帮助我们维护我们的 fragment 持有的数据。

现在我们有了包含在`view`中的膨胀布局，我们可以使用它来从布局中获取对我们的`Button`小部件的引用并监听点击。

最后，我们将`view`用作调用代码的返回值，如下所示：

```kt
return view
```

现在，我们可以按照通常的方式为按钮添加 lambda 来监听点击。在`onClick`函数中，我们显示一个弹出的`Toast`消息，以演示一切都按预期工作。

将此代码添加到`onCreateView`中的`return`语句之前，如下面的代码所示：

```kt
val button = view.findViewById(R.id.button) as Button

button.setOnClickListener(
  {
         Toast.makeText(activity,
               myString, Toast.LENGTH_SHORT).show()
  }
)
```

### 提示

请注意，在`makeText`中使用的`activity`属性是对包含`Fragment`的`Activity`的引用。这是为了显示`Toast`消息而需要的。

我们现在还不能运行我们的应用程序；它不会工作，因为还需要一步。我们需要创建一个`SimpleFragment`的实例并适当地初始化它。这就是`FragmentManager`将被介绍的地方。

以下代码使用`Activity`的`supportFragmentManager`属性。它基于我们的`SimpleFragment`类创建一个新的`Fragment`，使用`findFragmentByID`函数，并传入将容纳它的布局（在`Activity`内部）的 ID。

将此代码添加到`MainActivity.kt`的`onCreate`函数中，在调用`setContentView`之后：

```kt
// Create a new fragment using the manager
var frag = supportFragmentManager
         .findFragmentById(R.id.fragmentHolder)

// Check the fragment has not already been initialized
if (frag == null) {
   // Initialize the fragment based on our SimpleFragment
   frag = SimpleFragment()
         supportFragmentManager.beginTransaction()
               .add(R.id.fragmentHolder, frag)
               .commit()
}
```

现在运行应用程序，惊叹于我们可点击的按钮，它显示了一个使用`Toast`类的消息，并且创建它需要两个布局和两个完整的类：

![我们的第一个 fragment 应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_24_07.jpg)

如果你还记得在第二章中以这种方式做过，*Kotlin, XML 和 UI 设计师*，并且代码要少得多，那么很明显我们需要一个 fragment 现实检查来回答“为什么？”的问题！

# Fragment 现实检查

那么，这个 fragment 到底对我们有什么作用呢？如果我们根本不去理会 fragment，我们的第一个 fragment 迷你应用程序的外观和功能将是一样的。

实际上，使用片段使整个事情变得更加复杂！为什么我们要这样做呢？

我们有点知道这个问题的答案；只是根据我们目前所见，它并不是特别清楚。我们知道一个片段或多个片段可以添加到活动的布局中。

我们知道一个片段不仅包含自己的布局（视图），还包含自己的代码（控制器），虽然由一个活动托管，但实际上是相对独立的。

我们的快速应用程序只显示了一个片段的操作，但我们可以有一个托管两个或更多片段的活动。然后我们在单个屏幕上有效地显示了两个几乎独立的控制器。这听起来可能很有用。

然而，最有用的是，当活动启动时，我们可以检测我们的应用程序运行的设备的属性，也许是手机或平板电脑，是纵向还是横向模式。然后我们可以使用这些信息来决定同时显示一个或两个片段。

这不仅帮助我们实现了我们在本章开头讨论的真实应用部分中讨论的功能，而且还允许我们在两种可能的情况下使用完全相同的片段代码！

这确实是片段的本质。我们通过将功能（控制器）和外观（视图）配对成一堆片段来创建一个完整的应用程序，我们可以以几乎不用担心的方式以不同的方式重复使用它们。

缺失的环节是，如果所有这些片段都是完全功能的独立控制器，那么我们需要更多地了解如何实现我们的模型层。

当然，可以预见到一些障碍，所以看一下以下经常问的问题。

# 经常问的问题

Q）如果我们只有一个`ArrayList`，就像我们在“Note to self”应用程序中一样，它将去哪里？我们如何在片段之间共享它（假设所有片段都需要访问相同的数据）？

A）我们可以使用一种更加优雅的解决方案来创建一个模型层（数据本身和维护数据的代码）。当我们探索`NavigationDrawer`时，我们将看到这一点第二十六章，“使用导航抽屉和片段的高级 UI”，以及 Android 数据库第二十七章，“Android 数据库”。

# 总结

现在我们对片段的用途有了广泛的了解，以及如何开始使用它们，我们可以开始深入了解它们的使用。在下一章中，我们将制作一些以不同方式使用多个片段的应用程序。


# 第二十五章：使用分页和滑动的高级 UI

**分页**是从一页到另一页的行为，在 Android 上，我们通过在屏幕上滑动手指来实现这一点。当前页面会根据手指的移动方向和速度进行过渡。这是一个有用和实用的应用程序导航方式，但也许更重要的是，它是一种极其令用户满意的视觉效果。此外，就像`RecyclerView`一样，我们可以选择性地仅加载当前页面所需的数据，也许还有前后页面的数据。

正如您所期望的那样，Android API 有一些简单的解决方案来实现分页。

在本章中，我们将学习以下内容：

+   实现像照片库应用程序中可能找到的图像一样的分页和滑动

+   使用基于`Fragment`的布局实现分页和滑动，为用户提供通过滑动浏览整个用户界面的可能性

首先，让我们看一个滑动的例子。

# 愤怒的小鸟经典滑动菜单

在这里，我们可以看到著名的愤怒的小鸟关卡选择菜单展示了滑动/分页的功能：

![愤怒的小鸟经典滑动菜单](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_25_01.jpg)

让我们构建两个分页应用程序：一个带有图像，一个带有`Fragment`实例。

# 构建图库/滑块应用程序

在 Android Studio 中创建一个名为`Image Pager`的新项目。使用**空活动**模板，并将其余设置保持默认。

这些图像位于下载包中的`Chapter25/Image Pager/drawable`文件夹中。以下图表显示它们在 Windows 资源管理器中的位置：

![构建图库/滑块应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_25_02.jpg)

将图像添加到项目资源管理器中的`drawable`文件夹中，当然，您也可以添加更有趣的图像，也许是您拍摄的一些照片。

## 实现布局

对于一个简单的图像分页应用程序，我们使用`PagerAdapter`类。我们可以将其视为像`RecyclerApater`一样用于图像，因为它将处理在`ViewPager`小部件中显示图像数组。这与`RecyclerAdapter`非常相似，后者处理在`RecyclerView`中显示`ArrayList`的内容。我们只需要重写适当的函数。

要使用`PagerAdapter`实现图像库，我们首先需要在主布局中添加一个`ViewPager`小部件。因此，您可以清楚地看到所需的内容；以下是`activity_main.xml`的实际 XML 代码。编辑`layout_main.xml`使其看起来完全像这样：

```kt
<RelativeLayout xmlns:android=
   "http://schemas.android.com/apk/res/android"
    android:layout_width="fill_parent"
    android:layout_height="fill_parent" >

    <androidx.viewpager.widget.ViewPager
        android:id="@+id/pager"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content" />

</RelativeLayout>
```

略微不寻常命名的类`androidx.ViewPager.widget.ViewPager`是在发布`ViewPager`之前的 Android 版本中提供此功能的类。

接下来，就像我们需要一个布局来表示列表项一样，我们需要一个布局来表示`ViewPager`小部件中的项目，这种情况下是一个图像。以通常的方式创建一个新的布局文件，并将其命名为`pager_item.xml`。它将包含一个带有`id`属性为`imageView`的`ImageView`。

使用可视化设计工具来实现这一点，或者将以下 XML 复制到`pager_item.xml`中：

```kt
<RelativeLayout xmlns:android=
   "http://schemas.android.com/apk/res/android"
    android:layout_width="fill_parent"
    android:layout_height="fill_parent" >

    <androidx.viewpager.widget.ViewPager
        android:id="@+id/pager"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content" />

</RelativeLayout>
```

现在，我们可以开始编写我们的`PagerAdapter`类。

## 编写 PagerAdapter 类

接下来，我们需要继承自`PagerAdapter`来处理图像。创建一个名为`ImagePagerAdapter`的新类，并使其继承自`PagerAdapter`。此时代码应该如下所示：

```kt
class ImagePagerAdapter: PagerAdapter() {
}
```

将以下导入添加到`ImagePagerAdapter`类的顶部。通常我们依靠使用快捷键*Alt* + *Enter*来添加导入。这次我们做法略有不同，因为 Android API 中有一些非常相似的类，它们不适合我们的目标。

将以下导入添加到`ImagePagerAdapter`类中：

```kt
import android.content.Context
import android.view.LayoutInflater
import android.view.Vie
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.RelativeLayout

import androidx.viewpager.widget.PagerAdapter
import androidx.viewpager.widget.ViewPager
```

接下来，在类中添加一个构造函数，以便在创建实例时从`MainActivity`获取`Context`对象和一个`Int`数组（指向图像资源 ID）：

```kt
class ImagePagerAdapter(
        var context: Context,
 private var images: IntArray)
        : PagerAdapter() {

}
```

现在，我们必须重写`PagerAdapter`的必需函数。在`ImagePagerAdapter`类的主体内，添加重写的`getCount`函数，它简单地返回数组中图像 ID 的数量。该函数是该类内部使用的：

```kt
override fun getCount(): Int {
   return images.size
}
```

现在，我们必须重写`isViewFromObject`函数，它根据当前`View`是否与作为参数传入的当前`Object`相同或关联来返回`Boolean`。再次强调，这是该类内部使用的函数。在上一个代码之后，添加以下重写函数：

```kt
override fun isViewFromObject(
         view: View, `object`: Any)
       : Boolean {
   return view === `object`
}
```

现在，我们必须重写`instantiateItem`函数，这是我们大部分关注的工作所在。首先，我们声明一个新的`ImageView`对象，然后初始化一个`LayoutInflater`。接下来，我们使用`LayoutInflater`从我们的`pager_item.xml`布局文件中声明和初始化一个新的`View`。

在此之后，我们获取`pager_item.xml`布局内的`ImageView`的引用。现在，根据`instantiateItem`函数的`position`参数和`images`数组的适当 ID，我们可以将适当的图像添加为`ImageView`小部件的内容。

最后，我们使用`addView`将布局添加到`PagerAdapter`中，并从函数返回。

现在，添加我们刚刚讨论的代码：

```kt
override fun instantiateItem(
         container: ViewGroup,
         position: Int)
         : View {

  val image: ImageView
  val inflater: LayoutInflater =
        context.getSystemService(
        Context.LAYOUT_INFLATER_SERVICE)
        as LayoutInflater

  val itemView =
        inflater.inflate(
              R.layout.pager_item, container,
              false)

     // get reference to imageView in pager_item layout
     image = itemView.findViewById<View>(
           R.id.imageView) as ImageView

  // Set an image to the ImageView
  image.setImageResource(images[position])

  // Add pager_item layout as 
  // the current page to the ViewPager
  (container as ViewPager).addView(itemView)

  return itemView
}
```

我们必须重写的最后一个函数是`destroyItem`，当类需要根据`position`参数的值移除适当的项时，可以调用该函数。

在上一个代码之后，在`ImagePagerAdapter`类的闭合大括号之前添加`destroyItem`函数：

```kt
override fun destroyItem(
  container: ViewGroup, 
  position: Int, 
  `object`: Any) {

  // Remove pager_item layout from ViewPager
  (container as ViewPager).
        removeView(`object` as RelativeLayout)
}
```

正如我们在编写`ImagePagerAdapter`时所看到的，这里几乎没有什么。只是正确实现`ImagePagerAdapter`类用于在幕后顺利运行的重写函数。

现在，我们可以编写`MainActivity`类，它将使用`ImagePagerAdapter`。

## 编写 MainActivity 类

最后，我们可以编写我们的`MainActivity`类。与`ImagePagerAdapter`类一样，为了清晰起见，在类声明之前手动添加以下导入语句，如下面的代码所示：

```kt
import android.view.View
import androidx.viewpager.widget.ViewPager
import androidx.viewpager.widget.PagerAdapter
```

所有代码都放在`onCreate`函数中。我们使用`drawable-xhdpi`文件夹中添加的每个图像来初始化我们的`Int`数组。

我们以通常的方式使用`findViewByID`函数初始化`ViewPager`小部件。我们还通过传递`MainActivity`的引用和`images`数组来初始化我们的`ImagePagerAdapter`实例，这是我们之前编写的构造函数所要求的。最后，我们使用`setAdapter`将适配器绑定到 pager。

将`onCreate`函数编码为与以下代码完全相同的样式：

```kt
override fun onCreate(savedInstanceState: Bundle?) {
   super.onCreate(savedInstanceState)

   setContentView(R.layout.activity_main)

   // Grab all the images and stuff them in our array
   val images: IntArray = intArrayOf(
         R.drawable.image1,
         R.drawable.image2,
         R.drawable.image3,
         R.drawable.image4,
         R.drawable.image5,
         R.drawable.image6)

  // get a reference to the ViewPager in the layout
  val viewPager: ViewPager =
        findViewById<View>(R.id.pager) as ViewPager

  // Initialize our adapter
  val adapter: PagerAdapter =
        ImagePagerAdapter(this, images)

  // Binds the Adapter to the ViewPager
  viewPager.adapter = adapter

}
```

现在，我们准备运行应用程序。

## 运行画廊应用程序

在这里，我们可以看到我们`int`数组中的第一个图像：

![运行画廊应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_25_03.jpg)

向左和向右滑动一点，看到图像平稳过渡的愉悦方式：

![运行画廊应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_25_04.jpg)

现在，我们将构建一个具有几乎相同功能的应用程序，只是 pager 中的每个页面将是`Fragment`实例，它可以具有常规`Fragment`可以具有的任何功能，因为它们是常规`Fragments`。

在我们实现这之前，让我们学习一些有助于我们实现这一目标的 Kotlin 知识。

# Kotlin 伴生对象

伴生对象在语法上类似于内部类，因为我们将其声明在一个常规类内部，但请注意我们将其称为对象，而不是类。这意味着它本身是一个实例，而不是一个实例的蓝图。这正是它的作用。当我们在一个类内部声明一个伴生对象时，它的属性和函数将被所有常规类的实例共享。当我们想要一组常规类共享一组相关数据时，它非常完美。我们将在下一个应用程序中看到伴生对象的作用，也将在倒数第二章的 Age 数据库应用程序中看到它的作用。

# 构建一个 Fragment Pager/滑块应用程序

我们可以将整个`Fragment`实例作为`PagerAdapter`中的页面。这是非常强大的，因为我们知道，`Fragment`实例可以具有大量的功能 - 甚至是一个完整的 UI。

为了保持代码简洁和直观，我们将在每个`Fragment`布局中添加一个`TextView`，以演示滑块的工作原理。然而，当我们看到如何轻松地获取对`TextView`的引用时，我们应该很容易地添加我们迄今为止学到的任何布局，然后让用户与之交互。

### 注意

在下一个项目中，我们将看到另一种显示多个`Fragment`实例的方法，`NavigationView`，并且我们将实际实现多个编码的`Fragment`实例。

我们将首先构建滑块的内容。在这种情况下，内容当然是`Fragment`的一个实例。我们将构建一个简单的名为`SimpleFragment`的类，和一个简单的名为`fragment_layout`的布局。

你可能会认为这意味着每个幻灯片在外观上都是相同的，但我们将使用在实例化时由`FragmentManager`传入的 ID 作为`TextView`的文本。这样，当我们翻转/滑动`Fragment`实例时，每个实例都是一个新的不同实例。

当我们看到从列表中加载`Fragment`实例的代码时，很容易设计完全不同的`Fragment`类，就像我们以前做过的那样，并且可以为一些或所有幻灯片使用这些不同的类。当然，这些类中的每一个也可以使用不同的布局。

## 编写 SimpleFragment 类

与 Image Pager 应用程序一样，很难确定 Android Studio 需要自动导入哪些类。我们使用这些类是因为它们彼此兼容，如果让 Android Studio 建议导入哪些类，可能会出现错误。项目文件位于`Chapter25/Fragment Pager`文件夹中。

使用**空活动**模板创建一个名为`Fragment Slider`的新项目，并将所有设置保持默认设置。

现在，创建一个名为`SimpleFragment`的新类，继承自`Fragment`，并添加`import`语句，如下所示的代码：

```kt
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView

import androidx.fragment.app.Fragment

class SimpleFragment: Fragment() {
}
```

我们必须添加两个函数，第一个是`newInstance`，将包含在一个伴生对象中，我们将从`MainActivity`中调用它来设置并返回对`Fragment`的引用。以下代码创建了一个类的新实例，但它还将一个`String`放入`Bundle`对象中，最终将从`onCreateView`函数中读取。添加到`Bundle`中的`String`作为`newInstance`函数的唯一参数传入。

在`SimpleFragment`类的伴生对象中添加`newInstance`函数，如下所示：

```kt
class SimpleFragment: Fragment() {
// Our companion object which
// we call to make a new Fragment

companion object {
   // Holds the fragment id passed in when created
   val messageID = "messageID"

   fun newInstance(message: String)
               : SimpleFragment {
        // Create the fragment
        val fragment = SimpleFragment()

        // Create a bundle for our message/id
        val bundle = Bundle(1)
        // Load up the Bundle
        bundle.putString(messageID, message)
        fragment.arguments = bundle
        return fragment
   }
}
```

我们的`SimpleFragment`类的最终函数需要覆盖`onCreateView`，在这里，我们将像往常一样获取传入的布局的引用，并将我们的`fragment_layout` XML 文件加载为布局。

然后，第一行代码使用`getArguments.getString`和键值对的`MESSAGE`标识符从`Bundle`中解包`String`。

添加我们刚刚讨论过的`onCreateView`函数：

```kt
override fun onCreateView(
         inflater: LayoutInflater,
         container: ViewGroup?,
         savedInstanceState: Bundle?)
         : View? {

  // Get the id from the Bundle
  val message = arguments!!.getString(messageID)

  // Inflate the view as normal
  val view = inflater.inflate(
              R.layout.fragment_layout,
              container,
              false)

  // Get a reference to textView
  val messageTextView = view
        .findViewById<View>(R.id.textView) 
              as TextView

  // Display the id in the TextView
  messageTextView.text = message

  // We could also handle any UI
  // of any complexity in the usual way
  // And we will over the next two chapters
  // ..
  // ..

  return view
}
```

让我们也为`Fragment`制作一个超级简单的布局，当然，它将包含我们刚刚使用的`TextView`。

## fragment_layout

`fragment_layout`是我们制作过的最简单的布局。右键单击`layout`文件夹，选择**新建** | **资源布局文件**。将文件命名为`fragment_layout`，然后单击**确定**。现在，添加一个单独的`TextView`并将其`id`属性设置为`textView`。

现在我们可以编写`MainActivity`类，它处理`FragmentPager`并使我们的`SimpleFragment`实例活起来。

## 编写 MainActivity 类

这个类由两个主要部分组成；首先，我们将对重写的`onCreate`函数进行更改，其次，我们将实现一个内部类及其重写的`FragmentPagerAdapter`函数。

首先，添加以下导入：

```kt
import java.util.ArrayList

import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.FragmentPagerAdapter
import androidx.viewpager.widget.ViewPager
```

接下来，在`onCreate`函数中，我们创建一个`Fragment`实例的`ArrayList`，然后创建并添加三个`SimpleFragment`实例，传入一个数字标识符以打包到`Bundle`中。

然后，我们初始化`SimpleFragmentPagerAdapter`（我们很快将编写），传入我们的片段列表。

我们使用`findViewByID`获取对`ViewPager`的引用，并使用`setAdapter`将适配器绑定到它。

将以下代码添加到`MainActivity`的`onCreate`函数中：

```kt
public override fun onCreate(savedInstanceState: Bundle?) {
  super.onCreate(savedInstanceState)
  setContentView(R.layout.activity_main)

  // Initialize a list of three fragments
  val fragmentList = ArrayList<Fragment>()

  // Add three new Fragments to the list
  fragmentList.add(SimpleFragment.newInstance("1"))
  fragmentList.add(SimpleFragment.newInstance("2"))
  fragmentList.add(SimpleFragment.newInstance("3"))

  val pageAdapter = SimpleFragmentPagerAdapter(
              supportFragmentManager, fragmentList)

  val pager = findViewById<View>(R.id.pager) as ViewPager
  pager.adapter = pageAdapter

}
```

现在，我们将添加我们的`inner`类`SimpleFragmentPagerAdapter`。我们所做的就是在构造函数中添加一个`Fragment`实例的`ArrayList`，并用传入的列表进行初始化。

然后，我们重写`getItem`和`getCount`函数，这些函数在内部使用，方式与上一个项目中所做的方式相同。将我们刚讨论过的以下`inner`类添加到`MainActivity`类中：

```kt
private inner class SimpleFragmentPagerAdapter
   // A constructor to receive a fragment manager
   (fm: FragmentManager,
   // An ArrayList to hold our fragments
   private val fragments: ArrayList<Fragment>)
   : FragmentPagerAdapter(fm) {

   // Just two methods to override to get the current
   // position of the adapter and the size of the List
   override fun getItem(position: Int): Fragment {
          return this.fragments[position]
   }

  override fun getCount(): Int {
          return this.fragments.size
  }
}
```

我们需要做的最后一件事是为`MainActivity`添加布局。

## activity_main 布局

通过复制以下代码来实现`activity_main`布局。它包含一个小部件，一个`ViewPager`，很重要的是它来自正确的层次结构，以便与我们在此项目中使用的其他类兼容。

修改我们刚刚讨论的`layout_main.xml`文件中的代码：

```kt
<RelativeLayout xmlns:android=
      "http://schemas.android.com/apk/res/android"

      android:layout_width="match_parent"
      android:layout_height="match_parent"  
      tools:context=".MainActivity">

      <androidx.viewpager.widget.ViewPager
      android:id="@+id/pager"
      android:layout_width="wrap_content"
      android:layout_height="wrap_content" />

</RelativeLayout>
```

让我们看看我们的片段滑块在运行中的样子。

## 运行片段滑块应用程序

运行应用程序，然后您可以通过滑动左或右来浏览滑块中的片段。以下截图显示了当用户尝试在`List`中的最后一个`Fragment`之外滑动时，`FragmentPagerAdapter`产生的视觉效果：

![运行片段滑块应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_25_05.jpg)

# 摘要

在本章中，我们看到我们可以使用分页器来制作简单的图像库，或者通过整个 UI 的复杂页面进行滑动，尽管我们通过一个非常简单的`TextView`来演示这一点。

在下一章中，我们将看到另一个非常酷的 UI 元素，它在许多最新的 Android 应用程序中使用，可能是因为它看起来很棒，而且非常实用。让我们来看看`NavigationView`。


# 第二十六章：使用导航抽屉和 Fragment 的高级 UI

在本章中，我们将看到（可以说是）最先进的 UI。`NavigationView`或导航抽屉（因为它滑出内容的方式），可以通过在创建新项目时选择它作为模板来简单创建。我们将这样做，然后我们将检查自动生成的代码并学习如何与其交互。然后，我们将使用我们对`Fragment`类的所有了解来填充每个“抽屉”具有不同行为和视图。然后，在下一章中，我们将学习数据库，为每个`Fragment`添加一些新功能。

在本章中，将涵盖以下主题：

+   引入`NavigationView`小部件

+   开始使用年龄数据库应用

+   使用项目模板实现`NavigationView`

+   向`NavigationView`添加多个`Fragment`实例和布局

让我们来看看这个非常酷的 UI 模式。

# 引入 NavigationView

`NavigationView`有什么好处？可能首先吸引您注意的是它可以看起来非常时尚。看看下面的截图，展示了 Google Play 应用中`NavigationView`的运行情况：

![引入 NavigationView](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_01.jpg)

老实说，从一开始，我们的应用不会像 Google Play 应用中的那样花哨。但是我们的应用中将具有相同的功能。

这个 UI 的另一个亮点是它在需要时滑动隐藏或显示自己的方式。正是因为这种行为，它可以是一个相当大的尺寸，使得它在添加选项时非常灵活，并且当用户完成后，它会完全消失，就像一个抽屉一样。

### 提示

如果您还没有尝试过，我建议现在尝试一下 Google Play 应用，看看它是如何工作的。

您可以从屏幕的左边缘滑动拇指或手指，抽屉将慢慢滑出。当然，您也可以向相反方向再次滑动它。

导航抽屉打开时，屏幕的其余部分会略微变暗（如前一个截图所示），帮助用户专注于提供的导航选项。

在抽屉打开时，您还可以点击抽屉之外的任何地方，它将自行滑开，为布局的其余部分留出整个屏幕。

也可以通过点击左上角的菜单图标打开抽屉。

我们还可以调整和完善导航抽屉的行为，这将在本章末尾看到。

# 检查年龄数据库应用

在本章中，我们将专注于创建`NavigationView`并用四个`Fragment`类及其各自的布局填充它。在下一章中，我们将学习并实现数据库功能。

这是我们`NavigationView`的全貌。请注意，当使用`NavigationView`活动模板时，默认情况下提供了许多选项和大部分外观和装饰：

![检查年龄数据库应用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_02.jpg)

四个主要选项是我们将添加到 UI 中的。它们是**Insert**，**Delete**，**Search**和**Results**。接下来将展示布局并描述它们的目的。

## 插入

第一个屏幕允许用户将一个人的姓名和相关年龄插入到数据库中：

![插入](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_03.jpg)

这个简单的布局有两个`EditText`小部件和一个按钮。用户将输入姓名和年龄，然后点击**INSERT**按钮将它们添加到数据库中。

## 删除

这个屏幕甚至更简单。用户将在`EditText`小部件中输入姓名，然后点击按钮：

![删除](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_04.jpg)

如果输入的姓名存在于数据库中，则该条目（姓名和年龄）将被删除。

## 搜索

这个布局与上一个布局大致相同，但目的不同：

![搜索](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_05.jpg)

用户将在`EditText`中输入姓名，然后点击按钮。如果数据库中存在该姓名，那么它将显示出来，并显示匹配的年龄。

## 结果

这个屏幕显示了整个数据库中的所有条目：

![结果](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_06.jpg)

让我们开始使用应用和导航抽屉。

# 启动 Age Database 项目

在 Android Studio 中创建一个新项目。将其命名为`Age Database`，使用**Navigation Drawer Activity**模板，并将所有其他设置保持与本书中一致。在做其他任何事情之前，值得在模拟器上运行应用程序，看看作为模板的一部分自动生成了多少，如下面的截图所示：

![启动 Age Database 项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_07.jpg)

乍一看，它只是一个普通的布局，带有一个`TextView`。但是，从左边缘滑动，或者按菜单按钮，导航抽屉就会显示出来。

![启动 Age Database 项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_08.jpg)

现在，我们可以修改选项，并为每个选项插入一个`Fragment`实例（带有布局）。要理解它是如何工作的，让我们来看看自动生成的代码。

# 探索自动生成的代码和资源

在`drawable`文件夹中，有一些图标，如下面的截图所示：

![探索自动生成的代码和资源](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_09.jpg)

这些是通常的图标，也是出现在导航抽屉菜单中的图标。我们不会费心去更改它们，但如果你想个性化你的应用中的图标，通过本次探索最终应该清楚如何做到。

接下来，打开`res/menu`文件夹。请注意，那里有一个额外的文件，名为`activity_main_drawer.xml`。下面的代码是从这个文件中摘录出来的，所以我们可以讨论它的内容：

```kt
<group android:checkableBehavior="single">
   <item
         android:id="@+id/nav_camera"
         android:icon="@drawable/ic_menu_camera"
         android:title="Import" />
   <item
         android:id="@+id/nav_gallery"
         android:icon="@drawable/ic_menu_gallery"
         android:title="Gallery" />
   <item
         android:id="@+id/nav_slideshow"
         android:icon="@drawable/ic_menu_slideshow"
         android:title="Slideshow" />
   <item
         android:id="@+id/nav_manage"
         android:icon="@drawable/ic_menu_manage"
         android:title="Tools" />
</group>
```

请注意，在`group`标签中有四个`item`标签。现在，请注意从上到下的`title`标签（`Import`，`Gallery`，`Slideshow`和`Tools`）与自动生成的导航抽屉菜单中的前四个文本选项完全对应。另外，请注意在每个`item`标签中都有一个`id`标签，这样我们就可以在 Kotlin 代码中引用它们，还有一个`icon`标签，对应着我们刚刚看到的`drawable`文件夹中的图标之一。

另外，请查看`layout`文件夹中的`nav_header_main.xml`文件，其中包含了抽屉的头部布局。

其余的文件都如我们所料，但在 Kotlin 代码中还有一些要注意的关键点。这些都在`MainActivity.kt`文件中。现在打开它，我们来看看它们。

首先是`onCreate`函数中处理我们 UI 各个方面的额外代码。看看这段额外的代码，然后我们可以讨论它：

```kt
val toggle = ActionBarDrawerToggle(
         this, drawer_layout, 
         toolbar, 
         R.string.navigation_drawer_open, 
         R.string.navigation_drawer_close)

drawer_layout.addDrawerListener(toggle)

toggle.syncState()

nav_view.setNavigationItemSelectedListener(this)
```

代码获取了一个`DrawerLayout`的引用，它对应着我们刚刚看到的布局。代码还创建了一个`ActionBarDrawerToggle`的新实例，它允许控制或切换抽屉。代码的最后一行在`NavigationView`上设置了一个监听器。现在，每当用户与导航抽屉交互时，Android 都会调用一个特殊的函数。我所指的这个特殊函数是`onNavigationItemSelected`。我们将在一分钟内看到这个自动生成的函数。

接下来，看一下`onBackPressed`函数：

```kt
override fun onBackPressed() {
   if (drawer_layout.isDrawerOpen(GravityCompat.START)) {
         drawer_layout.closeDrawer(GravityCompat.START)
   } else {
         super.onBackPressed()
  }
}
```

这是`Activity`类的一个重写函数，它处理用户在设备上按返回按钮时发生的情况。如果抽屉打开，代码会关闭它；如果抽屉没有打开，代码会简单地调用`super.onBackPressed`。这意味着如果抽屉打开，按返回按钮会关闭抽屉；如果抽屉已经关闭，会使用默认行为。

现在，看一下`onNavigationItemSelected`函数，这对应着应用功能的关键部分：

```kt
override fun onNavigationItemSelected(
   item: MenuItem)
   : Boolean {

   // Handle navigation view item clicks here.
   when (item.itemId) {
         R.id.nav_camera -> {
               // Handle the camera action
         }
         R.id.nav_gallery -> {

         }
         R.id.nav_slideshow -> {

         }
         R.id.nav_manage -> {

         }
         R.id.nav_share -> {

         }
         R.id.nav_send -> {

         }
   }

   drawer_layout.closeDrawer(GravityCompat.START)
   return true
}
```

请注意，`when`块分支对应于`activity_main_drawer.xml`文件中包含的`id`值。这是我们将响应用户在导航抽屉菜单中选择选项的地方。目前，`when`代码什么也不做。我们将更改它以加载特定的`Fragment`以及其相关的布局到主视图中。这意味着我们的应用将根据用户从菜单中的选择具有完全不同的功能和独立的 UI，就像我们在第二十四章中讨论 MVC 模式时所描述的那样，*设计模式、多个布局和片段*。

让我们编写`Fragment`类和它们的布局，然后我们可以回来编写代码，使用它们在`onNavigationItemSelected`函数中。

# 编写片段类及其布局

我们将创建四个类，包括加载布局的代码以及实际的布局，但是在学习了 Android 数据库之后，我们不会将任何数据库功能放入 Kotlin 代码中。

当我们有了四个类和它们的布局后，我们将学习如何从导航抽屉菜单中加载它们。在本章结束时，我们将拥有一个完全可用的导航抽屉，让用户在片段之间切换，但是在下一章之前，这些片段不会有任何功能。

## 为类和布局创建空文件

通过右键单击`layout`文件夹并选择**新建** | **布局资源文件**来创建四个布局文件，它们的父视图都是垂直的`LinearLayout`。将第一个文件命名为`content_insert`，第二个为`content_delete`，第三个为`content_search`，第四个为`content_results`。其他选项可以保持默认值。

现在你应该有四个新的布局文件，其中包含`LinearLayout`父视图，如下截图所示：

![为类和布局创建空文件](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_10.jpg)

让我们编写 Kotlin 类。

## 编写类

通过右键单击包含`MainActivity.kt`文件的文件夹并选择**新建** | **Kotlin 文件/类**来创建四个新类。将它们命名为`InsertFragment`、`DeleteFragment`、`SearchFragment`和`ResultsFragment`。从名称上就可以看出哪些片段将显示哪些布局。

接下来，让我们为每个类添加一些代码，使这些类从`Fragment`继承并加载它们相关的布局。

打开`InsertFragment.kt`并编辑它，使其包含以下代码：

```kt
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup

import androidx.fragment.app.Fragment

class InsertFragment : Fragment() {
    override fun onCreateView(
         inflater: LayoutInflater,
         container: ViewGroup?,
         savedInstanceState: Bundle?)
         : View? {

         val view = inflater.inflate(
                R.layout.content_insert,
                container,
                false)

        // Database and UI code goes here in next chapter

        return view
    }
}
```

打开`DeleteFragment.kt`并编辑它，使其包含以下代码：

```kt
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup

import androidx.fragment.app.Fragment

class DeleteFragment : Fragment() {
    override fun onCreateView(
         inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState:
        Bundle?)
        : View? {

        val view = inflater.inflate(
               R.layout.content_delete,
               container,
               false)

        // Database and UI code goes here in next chapter

        return view
    }
}
```

打开`SearchFragment.kt`并编辑它，使其包含以下代码：

```kt
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup

import androidx.fragment.app.Fragment

class SearchFragment : Fragment() {
    override fun onCreateView(
         inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?)
        : View? {

         val view = inflater.inflate(
               R.layout.content_search,
               container,
               false)

        // Database and UI code goes here in next chapter

        return view
    }
}
```

打开`ResultsFragment.kt`并编辑它，使其包含以下代码：

```kt
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup

import androidx.fragment.app.Fragment

class ResultsFragment : Fragment() {

    override fun onCreateView(
         inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?)
         : View? {

        val view = inflater.inflate(
               R.layout.content_results,
               container,
               false)

        // Database and UI code goes here in next chapter

        return inflater.inflate(R.layout.content_results,
                container,
                false)
    }
}
```

每个类完全没有功能，除了在`onCreateView`函数中，从相关的布局文件加载适当的布局。

让我们为之前创建的布局文件添加 UI。

## 设计布局

正如我们在本章开头所看到的，所有的布局都很简单。让你的布局与我的完全相同并不是必要的，但是，如同往常一样，`id`属性值必须相同，否则我们在下一章中编写的 Kotlin 代码将无法工作。

## 设计 content_insert.xml

从**文本**类别的调色板中拖动两个**纯文本**小部件到布局中。记住**纯文本**小部件是`EditText`实例。现在，在两个**EditText**/**纯文本**小部件之后，拖动一个**按钮**到布局中。

根据这个表格配置小部件：

| 小部件 | 属性和值 |
| --- | --- |
| 顶部编辑文本 | id = `editName` |
| 顶部编辑文本 | 文本 = `姓名` |
| 第二个编辑文本 | id = `editAge` |
| 第二个编辑文本 | 文本 = `年龄` |
| 按钮 | id = `btnInsert` |
| 按钮 | 文本 = `插入` |

这是你的布局在 Android Studio 的设计视图中应该是这样的：

![设计 content_insert.xml](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_11.jpg)

## 设计 content_delete.xml

将**普通文本**/**EditText**小部件拖放到布局上方，下方是一个**按钮**。根据以下表格配置小部件：

| 小部件 | 属性值 |
| --- | --- |
| EditText | id = `editDelete` |
| EditText | 文本 = `名称` |
| 按钮 | id = `btnDelete` |
| 按钮 | 文本 = `删除` |

这是您在 Android Studio 的设计视图中的布局应该看起来的样子：

![设计 content_delete.xml](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_12.jpg)

## 设计 content_search.xml

将**普通文本**/**EditText**小部件拖放到布局上方，然后是一个**按钮**，然后是一个常规的**TextView**，然后根据以下表格配置小部件：

| 小部件 | 属性值 |
| --- | --- |
| EditText | id = `editSearch` |
| EditText | 文本 = `名称` |
| 按钮 | id = `btnSearch` |
| 按钮 | 文本 = `搜索` |
| TextView | id = `textResult` |

这是您在 Android Studio 的设计视图中的布局应该看起来的样子：

![设计 content_search.xml](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_13.jpg)

## 设计 content_results.xml

将单个`TextView`（这次不是**普通文本**/**EditText**）拖放到布局中。在下一章中，我们将看到如何将整个列表添加到这个单个`TextView`中。

根据以下表格配置小部件：

| 小部件 | 属性值 |
| --- | --- |
| TextView | id = `textResults` |

这是您在 Android Studio 的设计视图中的布局应该看起来的样子：

![设计 content_results.xml](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_26_14.jpg)

现在，我们可以使用基于`Fragment`类和它们的布局的类。

# 使用`Fragment`类及其布局

这个阶段有三个步骤。首先，我们需要编辑导航抽屉的菜单，以反映用户的选项。接下来，我们需要在布局中添加一个`View`实例，以容纳当前活动的`Fragment`实例，最后，我们需要在`MainActivity.kt`中添加代码，以在用户点击导航抽屉菜单时在不同的`Fragment`实例之间切换。

## 编辑导航抽屉菜单

在项目资源管理器的`res/menu`文件夹中打开`activity_main_drawer.xml`文件。编辑`group`标签中的代码，以反映我们的**插入**、**删除**、**搜索**和**结果**菜单选项：

```kt
<group android:checkableBehavior="single">
   <item
         android:id="@+id/nav_insert"
         android:icon="@drawable/ic_menu_camera"
         android:title="Insert" />
   <item
         android:id="@+id/nav_delete"
         android:icon="@drawable/ic_menu_gallery"
         android:title="Delete" />
   <item
         android:id="@+id/nav_search"
         android:icon="@drawable/ic_menu_slideshow"
         android:title="Search" />
   <item
         android:id="@+id/nav_results"
         android:icon="@drawable/ic_menu_manage"
         android:title="Results" />
</group>
```

### 提示

现在是一个很好的时机，可以向`drawable`文件夹添加新的图标，并编辑前面的代码以引用它们，如果您想使用自己的图标。

## 向主布局添加一个占位符

在布局文件夹中打开`content_main.xml`文件，并在`ConstraintLayout`的闭合标签之前添加以下突出显示的 XML 代码：

```kt
<FrameLayout
 android:id="@+id/fragmentHolder"
 android:layout_width="0dp"
 android:layout_height="0dp"
 app:layout_constraintBottom_toBottomOf="parent"
 app:layout_constraintEnd_toEndOf="parent"
 app:layout_constraintStart_toStartOf="parent"
 app:layout_constraintTop_toTopOf="parent"> 
</FrameLayout>

</androidx.constraintlayout.widget.ConstraintLayout>
```

现在，我们有一个`id`属性为`fragmentHolder`的`FrameLayout`，我们可以引用并将所有`Fragment`实例的布局加载到其中。

## 编写 MainActivity.kt 文件

打开`MainActivity`文件，并编辑`onNavigationItemSelected`函数，以处理用户可以选择的所有不同菜单选项：

```kt
override fun onNavigationItemSelected(
  item: MenuItem): 
  Boolean {

  // Create a transaction
  val transaction = 
        supportFragmentManager.beginTransaction()

  // Handle navigation view item clicks here.
  when (item.itemId) {
        R.id.nav_insert -> {
              // Create a new fragment of the appropriate type
              val fragment = InsertFragment()
              // What to do and where to do it
              transaction.replace(R.id.fragmentHolder, fragment)
    }
    R.id.nav_search -> {
              val fragment = SearchFragment()
              transaction.replace(R.id.fragmentHolder, fragment)
    }
    R.id.nav_delete -> {
              val fragment = DeleteFragment()
              transaction.replace(R.id.fragmentHolder, fragment)
    }
    R.id.nav_results -> {
      val fragment = ResultsFragment()
      transaction.replace(R.id.fragmentHolder, fragment)
    }

  }

   // Ask Android to remember which
   // menu options the user has chosen
   transaction.addToBackStack(null);

  // Implement the change
  transaction.commit();

   drawer_layout.closeDrawer(GravityCompat.START)
   return true
}
```

让我们来看一下我们刚刚添加的代码。大部分代码应该看起来很熟悉。对于我们的每个菜单选项，我们创建一个相应类型的新`Fragment`实例，并将其插入到`id`值为`fragmentHolder`的`FrameLayout`中。

`transaction.addToBackStack`函数调用意味着所选的`Fragment`将按顺序与其他`Fragment`一起被记住。这样做的结果是，如果用户选择**插入**片段，然后选择**结果**片段，然后点击返回按钮，应用程序将把用户返回到**插入**片段。

现在可以运行应用程序，并使用导航抽屉菜单在所有不同的`Fragment`实例之间切换。它们看起来就像本章开头的图片一样，但它们还没有任何功能。

# 摘要

在本章中，我们看到了拥有一个吸引人和令人愉悦的 UI 是多么简单，尽管我们的`Fragment`实例还没有任何功能，但一旦我们学会了数据库，它们就已经准备就绪了。

在下一章中，我们将学习关于数据库的一般知识，以及 Android 应用程序可以使用的特定数据库，在我们为`Fragment`类添加功能之前。
