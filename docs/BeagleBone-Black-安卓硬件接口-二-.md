# BeagleBone Black 安卓硬件接口（二）

> 原文：[`zh.annas-archive.org/md5/8608566C49BFB6DF1A157117C5F5286A`](https://zh.annas-archive.org/md5/8608566C49BFB6DF1A157117C5F5286A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：创建完整的接口解决方案

在本书的前几章中，你使用 GPIOs、I2C 和 SPI 与设备进行接口。你使用`AsyncTask`在后台线程中执行硬件接口，并探讨了如何构建一个应用以与这些线程交互。

在本章中，你将把这些概念结合起来，创建一个使用这三种接口方法的电路，并探索一个将所有接口结合在一起使用的应用，以构建一个复杂的系统。

在本章中，我们将讨论以下主题：

+   构建完整的接口电路

+   探索最终的示例应用

# 构建完整的接口电路

本章使用的接口电路是第 3、4 和 5 章描述的电路的组合。如果你已经成功构建了之前章节的电路，那么你已经很好地理解了本章电路的组成。如果你按照早期章节的说明紧密构建了这些电路，请将它们留在面包板上，以节省你的努力。

下图展示了传感器开发板、FRAM 开发板、LED、按钮开关、电阻与 BBB 之间的连接。如果你还没有完成，请回顾第 3、4 和 5 章，详细了解如何构建电路的 GPIO、FRAM 和 SPI 部分。

![构建完整的接口电路](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00028.jpeg)

使用 GPIOs、I2C 和 SPI 组件与 BBB 进行接口的完整硬件接口电路

# 探索完整的示例应用

在本节中，你将研究一个示例 Android 应用，该应用在 BBB 上执行 GPIO、I2C 和接口。该应用旨在演示如何使用 PacktHAL 从实际应用中的一组接口函数执行各种硬件任务。与之前的示例应用不同，它们从用户那里获取输入，而这个应用直接从硬件本身获取所有输入。这需要比早期应用更复杂的方法。

在深入探讨应用代码之前，你必须在你的开发系统上安装代码，并在你的 Android 系统上安装应用。该应用的源代码以及预编译的`.apk`包位于`chapter6.tgz`文件中，可以从 Packt 网站下载。按照第三章《使用 GPIO 处理输入和输出》中描述的过程，下载并将应用添加到你的 Eclipse ADT 环境中。

## 应用的用户界面

在 Android 系统上启动`complete`应用程序以查看应用程序的 UI。如果你使用的是触摸屏保护盖，只需在屏幕上轻触`complete`应用程序的图标即可启动应用程序并与其 UI 交互。如果你使用 HDMI 进行视频输出，请将 USB 鼠标连接到 BBB 的 USB 端口，并使用鼠标点击传感器应用程序图标以启动应用程序。

应用程序使用一个非常简单的 UI，在单个活动中默认显示两个文本视图，这是`MainActivity`。

![应用程序的用户界面](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00029.jpeg)

在从传感器接收到第一组样本之前，完整应用程序屏幕的外观。

这个应用程序中没有按钮或其他 UI 元素，因为用户与应用程序的唯一交互是通过电路的 GPIO 按钮开关。当用户按下开关时，应用程序会执行一系列硬件接口操作：

+   LED 灯将点亮以通知用户开关已被识别为按下状态。在列表上的所有事件发生之前，LED 灯将保持亮起。当 LED 灯亮起时，任何进一步的开关输入都会被忽略。

+   从传感器获取温度和压力样本，并将其写入 FRAM。

+   从 FRAM 读取以获取存储的温度和压力样本值。

+   温度和压力样本的值显示在应用程序的 UI 中。

+   将会发生 1 秒钟的延迟。

+   LED 灯将熄灭，此时可以再次按下开关以触发另一个样本-存储-检索-显示周期。

应用程序执行的各种操作使其接口行为比本书中之前示例应用程序更为复杂。这个应用程序不仅与单个硬件组件接口，而是同时与 GPIO、I2C 和 SPI 设备接口，以提供具有持久存储的完整传感器解决方案。然而，它基于本书中其他示例应用程序所展示的相同的基本接口概念。

## 了解应用程序中的硬件轮询。

之前的程序要么直接使用按钮的`onClick()`处理程序与硬件（GPIOs）接口，要么触发`AsyncTask`（I2C 和 SPI）的实例化和执行以与硬件接口。在这两种情况下，与硬件的接口都是由应用程序中的软件事件，即`onClick()`处理程序的执行触发的。

然而，在本章的应用程序中，我们希望响应开关被按下产生的硬件事件来触发硬件接口。监听硬件事件是接口的一个重要部分，因为它允许硬件在发生感兴趣的事件时通知我们。我们并不总是能够告诉硬件执行某项操作并期待硬件执行。有时，硬件需要通知我们发生了某个事件。

当从内核驱动程序与硬件接口时，驱动程序可以通过注册在硬件中断发生时通知其的机制来获知感兴趣的硬件事件。硬件中断会立即告诉内核硬件发生了值得注意的事情，并且内核将停止当前操作，以允许适当的内核驱动程序处理中断。

由于我们的应用程序是在用户空间执行更高级的接口逻辑，因此我们无法注册中断来通知我们感兴趣的事件发生的时间。这种硬件事件可能随时异步发生，所以应用程序必须不断轮询（或检查）开关的状态，以确定它是否被按下。通常应用程序不会轮询事件，因为它们依赖于 Android 框架在发生有趣的事情时通知它们，但是当应用程序在没有管理器帮助的情况下执行硬件接口时，轮询变得必要。

应用程序轮询硬件的速度越快，错过感兴趣硬件事件发生的几率就越小。然而，在紧密循环中不断轮询是一个糟糕的想法，因为它会不断消耗 CPU 周期（以及移动设备中的电池寿命），这些资源可以更好地用在其他地方。如果你的应用程序中包含轮询，你必须找到一个性能和资源使用之间的良好平衡。

在 UI 线程的上下文中放置一个轮询循环是一个糟糕的做法。请记住，在 UI 线程上下文中执行处理程序方法的时间过长将导致 Android 触发 ANR 对话框。为了避免这个问题，应用程序必须实例化`AsyncTask`，它在后台线程中执行硬件轮询。本书前面的示例应用程序使用了`AsyncTask`线程与硬件设备进行通信，但`AsyncTask`线程是短命的。`AsyncTask`线程的后台线程仅在它与硬件接口时活跃。一旦完成接口操作，线程就会终止。如果应用程序需要再次与硬件通信，会实例化一个新的`AsyncTask`线程并通过其`execute()`方法启动。

由于我们的应用程序必须使用`AsyncTask`不断轮询开关以检查用户输入，因此应用程序中使用的`AsyncTask`线程是一个长生命周期的线程。应用程序不是只在需要与硬件通信的时刻实例化并调用`execute()`方法，而是在每次进入**恢复状态**时实例化并执行`AsyncTask`。`AsyncTask`线程在后台继续执行，直到应用程序进入**暂停状态**。

### 注意

要了解 Android 应用活动在各种生命周期状态之间转换的详细信息，例如恢复状态和暂停状态，请参考官方 Android 开发者文档：[`developer.android.com/training/basics/activity-lifecycle/index.html`](http://developer.android.com/training/basics/activity-lifecycle/index.html)。

## 使用长生命期线程的 AsyncTask

在我们之前的示例应用中，已经使用了`AsyncTask`基类中的四种方法。这些方法用于在`AsyncTask`中实现短生命期和长生命期的线程：

+   `onPreExecute()`

+   `doInBackground()`

+   `onPostExecute()`

+   `execute()`

在本章中，你将使用`AsyncTask`类的五种附加方法。这些附加方法可用于增强短生命期线程的功能，几乎总是用于长生命期后台线程与线程通信，并在其运行时接收反馈：

+   `cancel()`

+   `onCancelled()`

+   `isCancelled()`

+   `publishProgress()`

+   `doPublishProgress()`

`cancel()`、`onCancelled()`和`isCancelled()`方法用于在应用的主活动`MainActivity`离开恢复状态时停止当前正在执行的`AsyncTask`方法。`cancel()`方法从 UI 线程上下文中调用，通知`AsyncTask`类已被取消并应停止执行。调用`cancel()`会触发在`AsyncTask`线程上下文中调用`onCancelled()`方法。然后`onCancelled()`给`AsyncTask`类一个执行任何必要清理任务的机会。`isCancelled()`方法可以在任何时候从`AsyncTask`线程上下文中调用，以确定是否已调用`cancel()`和`onCancelled()`。这个方法通常在`doInBackground()`方法内的循环中调用。

`publishProgress()`和`doPublishProgress()`方法允许`AsyncTask`线程通知 UI 线程应通过应用 UI 向用户显示的任何信息。例如，如果一个`AsyncTask`线程正在从网络复制一个大文件，这两个方法会通知 UI 线程已复制的文件部分和剩余文件传输的预计时间。UI 线程然后可以更新 UI 以显示这些信息，让应用的用户了解`AsyncTask`线程的进度。

早前章节中的示例应用没有使用这五个新的`AsyncTask`方法，因为那些应用使用的`AsyncTask`方法是短生命周期的线程，并通过`onPostExecute()`方法更新屏幕。由于`onPostExecute()`方法在 UI 线程中执行，所以那些应用中没有使用`publishProgress()`和`doPublishProgress()`的必要。那些应用中的`AsyncTask`线程在应用处于恢复状态时执行，而且线程生命周期非常短，因此没有必要使用`cancel()`或`onCancelled()`来终止线程的执行。由于那些应用在它们的`doInBackground()`方法中没有使用循环，所以也没有必要使用`isCancelled()`。

## 使用 HardwareTask 类

与前面章节中的示例应用类似，`complete`应用使用了一个从`AsyncTask`派生的`HardwareTask`类。所有硬件接口都是通过`HardwareTask`中的方法完成的。

![使用 HardwareTask 类](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00030.jpeg)

在其中执行 HardwareTask 方法和 PacktHAL 函数的线程上下文。此图像中的 JNI 函数已经将它们的函数名前缀缩短为 HardwareTask。

传感器应用的`HardwareTask`类提供了七个`native`方法，用于调用与 GPIO、FRAM 和传感器硬件接口相关的 PacktHAL JNI 函数：

```java
public class HardwareTask extends AsyncTask<Void, Void, Boolean> {

  private native boolean openHardware();
  private native boolean pollButton();
  private native boolean changeLED(boolean lit);
  private native boolean readSensor();
  private native float getSensorTemperature();
  private native float getSensorPressure();
  private native boolean closeHardware();
```

由于大部分硬件接口的细节都被封装在 PacktHAL 函数中，并且对`complete`应用隐藏，除了一个方法之外，这些方法都不接受任何参数。它们只是通过 PacktHAL JNI 包装函数调用其对应的 PacktHAL 函数。这个例外是`changeLED()`方法，它接受一个参数来指定 LED 是打开还是关闭。

在`complete`应用中，当`MainActivity`类变为恢复状态时，`MainActivity`类的`onResume()`方法会实例化一个新的`HardwareTask`类：

```java
    public void onResume() {
        super.onResume();

        // Create our background hardware communication thread
        hwTask = new HardwareTask();
        hwTask.pollHardware(this);
    }
```

`pollHardware()`方法通过调用基`AsyncTask`类的`execution()`方法创建一个新线程，开始硬件接口过程。

```java
    public void pollHardware(Activity act) {
      mCallerActivity = act;
      execute();
    }
```

当`MainActivity`类变为暂停状态时，`MainActivity`类的`onPause()`方法会停止`AsyncTask`类的执行：

```java
    public void onPause() {
        super.onPause();

        // Release the hardware when the app is paused
        if (hwTask != null) {
          hwTask.cancel(true);
          hwTask = null;
        }
    }
```

`AyncTask`基类的`cancel()`方法通过调用`HardwareTask`中的`onCancelled()`方法开始取消正在执行的`AsyncTask`线程的过程。除了通知`AsyncTask`基类执行已被取消之外，在`HardwareTask`类中还设置了`isDone`布尔标志：

```java
    protected void onCancelled() {
        Log.i("HardwareTask", "Cancelled.");
        isDone = true;
    }
```

一旦`MainActivity`转变为恢复状态，`HardwareTask`的`pollHardware()`方法就会开始执行`AsyncTask`线程。在`onPreExecute()`中，重置`isDone`标志，并通过`openHardware()`方法初始化 GPIO、I2C 和 SPI 设备。如果硬件初始化成功，接下来会通过`changeLED()`调用关闭 LED：

```java
protected void onPreExecute() {    
    Log.i("HardwareTask", "onPreExecute");
    isDone = false;
    ...
    if (!openHardware()) {
      Log.e("HardwareTask", "Error opening hardware");
      isDone = true;
    } else {
      changeLED(false);
    }
  }
```

`onPreExecute()` 完成后，`AsyncTask` 后台线程开始运行。`doInBackground()` 方法开始执行。由于这是一个长生命周期的线程，`doInBackground()` 中有一个 `while` 循环，它会一直执行，直到被主 UI 线程取消：

```java
protected Boolean doInBackground(Void... params) { 

      ...

      // Poll the button until an error or done
      while (!isDone && !isCancelled()) {
```

循环开始时通过轮询推按按钮开关的状态。如果开关被按下，硬件接口逻辑将开始与 FRAM 和传感器通信。如果开关未被按下，则跳过接口逻辑。在这两种情况下，通过 `Thread.sleep()` 方法调用添加了短暂的延迟，以使后台线程有机会休眠并允许其他线程运行。这限制了后台线程的资源消耗，并给其他进程和线程运行的机会：

```java
      while (!isDone && !isCancelled()) {
         if (pollButton()) {
...
         }
         Thread.sleep(100);
      }
      ...        
      return false;
}
```

如果 `pollButton()` 方法表明按钮被按下，硬件接口逻辑开始执行。这会调用各种本地方法，从而调用 PacktHAL JNI 函数。

首先，`changeLED()` 函数会点亮 LED，让用户知道即将进行采样：

```java
            if (!changeLED(true)) {
               Log.e("HardwareTask", "Unable to turn LED on");
            }
```

接下来，获取传感器样本并将结果存储在 FRAM 中。`readSensor()` 本地方法与传感器交互以获取样本数据，然后将温度和压力样本存储在 FRAM 内存的前八个字节中：

```java
            if (!readSensor())
            {
               Log.e("HardwareTask", "Unable to read sensor");
            }
```

### 注意

温度数据以 4 字节的浮点数形式存储在 FRAM 的前四个字节中，压力数据以 4 字节的浮点数形式存储在 FRAM 的后四个字节中。如果你对在本地代码中如何实现这一点感兴趣，可以查看 PacktHAL 中 `jni/jni_wrapper.c` 文件中的 `Java_com_packt_complete_HardwareTask_readSensor()` 函数。

之后，访问 FRAM 以获取温度和压力样本：

```java
            temperature = getSensorTemperature();
            pressure = getSensorPressure();
```

最后，通过 `publishProgress()` 方法在主 UI 线程中更新新的样本数据。线程休眠 1 秒后，LED 熄灭。此时，`pollButton()` 检查完成，`while` 循环再次开始：

```java
            publishProgress();
            Thread.sleep(1000);
            if (!changeLED(false)) {
               Log.e("HardwareTask", "Unable to turn LED off");
            }
         } // End of pollButton() check
```

`publishProgress()` 方法触发 `HardwareTask` 的 `onProgressUpdate()` 方法，该方法在 UI 线程中执行。`onProgressUpdate()` 方法调用 `MainActivity` 类的 `updateSensorData()` 方法：

```java
   protected void onProgressUpdate(Void... values) {
      ((MainActivity)mCallerActivity).
         updateSensorData(temperature, pressure);
   }
```

`MainActivity` 类中的 `updateSensorData()` 方法会更新应用的 UI，并为用户提供 `Toast` 消息：

```java
    public void updateSensorData(float temperature, float pressure) {
      Toast toast = Toast.makeText(getApplicationContext(), 
          "Updating sensor data", Toast.LENGTH_SHORT);
      TextView tv = (TextView) findViewById(R.id.temperatureTextView);    
       tv.setText("Temperature: " + temperature);

    tv = (TextView) findViewById(R.id.pressureTextView);
       tv.setText("Pressure: " + pressure);

       toast.show();
    }
```

`HardwareTask` 类的 `doInBackground()` 方法中的主要轮询 `while` 循环最终会因为硬件接口初始化失败或被 `MainActivity` 取消的基础 `AsyncTask` 方法而退出。循环完成后，`doInBackground()` 将退出，`AsyncTask` 后台线程将终止。然后 `onPostExecute()` 方法将执行任何必要的清理工作，例如关闭硬件接口：

```java
   protected void onPostExecute(Boolean result) {
    if (!closeHardware()) {
      Log.e("HardwareTask", "Error closing hardware");
    }
       ...
    }
```

`HardwareTask` 实例现在已经完成了它的后台线程工作。如果 `MainActivity` 返回到恢复状态，将会实例化一个新的 `HardwareTask` 实例。这个 `HardwareTask` 实例将创建另一个长期运行的后台线程，硬件接口过程将重复进行。

### 提示

**你准备好迎接挑战了吗？**

既然你已经看到了完整应用程序的所有部分，为何不修改它以添加一些新的功能呢？作为一个挑战，尝试将应用程序修改为在按下按钮后持续采集样本。如果短时间按下按钮，停止采集样本。我们在 `chapter6_challenge.tgz` 文件中提供了一个可能的实现，你可以在 Packt 网站上下载。

# 总结

在本章中，我们介绍了用于硬件接口的长生命周期线程的概念。你构建了一个电路，将 GPIO 按钮开关、GPIO LED、FRAM 设备以及温度和压力传感器连接到 BBB。与之前章节中的示例应用程序不同，本章中的示例应用程序使用轮询来持续监控硬件的状态。你还探索了使用 `AsyncTask` 类的五种附加方法，用于后台线程和应用程序主 UI 线程之间的通信和控制。

现在你已经使用应用程序学习了与 Android 硬件接口的许多基本概念，是时候关注更大的画面，了解如何将你的原型解决方案转变为更持久的解决方案。

在下一章中，你将学习如何将你的解决方案与 Android 框架集成，将你的解决方案与 BBB 可用的其他 cape 结合，以及你可以用于未来接口项目中的其他接口。


# 第七章：从这里出发

在上一章中，我们研究了 Android 应用如何同时与 GPIO、I2C 和 SPI 接口，以提供完整的硬件接口解决方案。尽管您可能认为这涵盖了 Android 下硬件接口的大部分问题，但还有许多其他因素需要考虑。

在本章中，我们将涵盖以下主题：

+   将您的解决方案集成到 Android 中

+   将您的硬件与其他硬件结合

+   探索 BBB 的其他接口

# 将您的解决方案与 Android 集成

BBB 提供了丰富的硬件功能，您在项目中使用的特定功能会随着系统中使用的 cape 和覆盖物的改变而变化。尽管这在原型设计期间为您提供了很大的灵活性，但您最终可能会将自定义硬件设计最终确定为一个单一的静态配置，并决定将其作为一个永久的基于 Android 的解决方案。

本书中的示例采用了让应用直接访问 BBB 硬件的设计决策。虽然这种方法使得创建硬件接口的 Android 应用变得简单，但这并不是理想的方法。一旦您有了满意的硬件设计并且软件能够正确地与硬件接口，那么就是完全将您的解决方案与 Android 集成的时候了。根据您的硬件解决方案的复杂程度，您可能最终会创建自定义内核设备驱动，甚至修改 Android OS 框架内的管理器！

## 创建自定义内核和 Device Tree

创建永久性 Android 解决方案的第一步是确保系统中 Linux 方面的所有内容都处于应有的状态。这意味着所有硬件支持（例如项目中需要的 Linux 内核驱动）应在内核中启用并配置，并在内核的 Device Tree 中分配（用于引脚复用和资源分配）。理想情况下，您需要的所有内容都应该直接静态构建到内核和 Device Tree 中。这样可以消除通过`init.{ro.hardware}.rc`文件内执行的显式命令加载覆盖物和内核模块的需求。

对于准备项目内核空间的建议是在 Linux 环境中开发这些部分。Linux 环境为内核驱动开发和调试提供了更多工具，你可以快速、轻松地构建独立的用户空间二进制文件，通过`open()`、`read()`、`write()`和`ioctl()`函数调用来与自定义和现有内核驱动交互。Linux 用户空间二进制文件的代码-编译-测试-调试周期可以非常快，因为包括编译器和调试器在内的完整开发工具链在 Linux 下都是可用的。在 Android 下，你必须使用 Android NDK 在开发机器上构建这样的测试二进制文件，然后使用`adb`将它们推送到 Android 系统上进行测试。这使得开发周期变得既慢又困难。

为你的解决方案开发一个静态的 Device Tree 需要类似的过程。Device Tree 及其覆盖层是使用`dtc`工具编译的，这个工具在 Linux 下可用，但在 Android 下不可用。使用标准的 Linux 内核调试技术，你可以开发和故障排除一个覆盖层，为你的项目复用引脚，并为这些引脚分配必要的内核驱动。一旦你的覆盖层正常工作，你可以将覆盖层永久地集成到 Device Tree 中。

### 提示

**我在哪里可以了解更多关于 BBB 的 Linux 开发？**

网上有许多教程和资源可以帮助你了解为 BBB 开发 Linux 软件和 Device Tree 覆盖层。我们能向你推荐的最好资源是 Derek Molloy 创建的 BeagleBone 视频教程系列。这些教程涵盖了诸如 C/C++开发环境设置和配置、调试、Device Tree 覆盖层创建和故障排除等主题。他们还有各种代码和电路示例，帮助你入门。你可以在 Derek 网站的 BeagleBone 部分观看这些教程，网址是[`derekmolloy.ie/beaglebone`](http://derekmolloy.ie/beaglebone)。

## 将硬件通信添加到内核中

虽然直接与 GPIO 和 I2C 及 SPI 总线接口很方便，但这并不是与硬件接口最高效的方式。在 I2C 存储和检索数据的章节中，I2C FRAM 的例子使用了 24c256 内核驱动来处理与 FRAM 芯片通信的低级细节。你能想象直接与 FRAM 芯片接口需要实现每一个细节会有多困难吗？除了需要了解 BBB 和 FRAM 芯片之间通信协议的每一个细节之外，这些协议还可能需要严格的定时保证，这在用户空间很难或不可能满足。

在用户空间与硬件接口不可行的情况下，使用内核驱动程序是必要的。内核驱动程序封装了与特定硬件通信的细节。这简化了接口应用，将这些细节保留在应用程序实现之外。内核驱动程序在与硬件通信时还提供了更为严格的时序保证。这是因为内核对于调度内核驱动通信事件以实现必要的最后期限有更深入的了解。在用户空间，如果内核的任务调度器决定给另一个进程执行的机会，进程可能会随时被挂起。即使用户空间进程的优先级大大提高，与基于内核的活动相比，它的调度优先级仍然会低。

创建内核驱动程序可能相当复杂，这远远超出了本书的范围。但是，如果你发现自己试图在与某块硬件通信时满足非常严格的时序限制，你最终可能需要探索内核设备驱动程序开发的细节。

### 提示

**我在哪里可以了解更多关于开发内核驱动程序的信息？**

学习内核驱动程序开发最好的起点是 Corbet、Rubini 和 Kroah-Hartman 所著的《Linux 设备驱动》一书。这本书提供了详尽的指导，带你了解开发过程。更好的是，这本书的第三版可以免费下载，网址是[`lwn.net/Kernel/LDD3`](http://lwn.net/Kernel/LDD3)。第三版最初于 2005 年出版，所以它有点过时，但书中提出的中心概念仍然是有效的。

## 集成到现有管理器中

在第五章中，*使用 SPI 与高速传感器接口*，你与基于 SPI 的温度和压力传感器进行了接口。虽然你使用 `spidev` 内核驱动从一个单一应用与传感器通信，但让管理器与传感器通信会更清晰。这样，所有应用都可以通过与管理器通信来请求访问传感器数据，而不是必须了解 SPI 通信的许多细节以及它们之间的协调访问。这也限制了哪些应用有权与 `spidev` 驱动程序交互。

实际上，Android 已经有一个管理器 `Android.SensorManager`，它旨在与手机和平板电脑中常见的硬件传感器资源进行通信。应用通过请求管理器的一个实例，然后请求代表特定类型传感器的对象来与管理器通信：

```java
Private final SensorManager mSensorManager;
Private final Sensor mPressure;
Private final Sensor mTemperature;

Public SensorActivity() {
  mSensorManager =
   (SensorManager)getSystemService(SENSOR_SERVICE);mPressure = 
    mSensorManager.getDefaultSensor(Sensor.TYPE_PRESSURE);
  mTemperature =
    mSensorManager.getDefaultSensor(Sensor.TYPE_TEMPERATURE);
}
```

如果`SensorManager`扩展到与您在第五章，*使用 SPI 与高速传感器接口*中使用的 SPI 传感器进行接口，那么您的应用只需几行 Java 代码就可以通过`SensorManager`与传感器通信！更妙的是，`spidev`设备的文件系统权限不需要设置为如此不安全的状态，以便应用与传感器通信。不幸的是，由于一些原因，将新的硬件功能集成到现有的管理器中可能会相当困难：

+   您必须重新构建 Android 的相应部分，这通常需要您至少一次完整构建 Android 源代码库。对于没有经验的人来说，这是一个耗时（且常常令人困惑）的过程。Android 开源项目在[`source.android.com/source`](https://source.android.com/source)提供了关于如何从源代码构建 Android 的指导。

+   必须将您新硬件的附加接口逻辑添加到您正在集成的管理器的 HAL 中。虽然这通常相当直接，但管理器 HAL 的部分可能散布在 Android 代码库的各个地方。

+   新硬件必须符合由管理器提供的框架 API 方法。除非您愿意打破 API 兼容性，向特定管理器类中添加额外的属性和方法，否则您必须确保您的硬件符合管理器提供的现有接口。

尽管这种集成可能比较困难，但通常非常直接。由于 Android 设计时考虑了平板电脑和手机，任何可能成为移动设备平台一部分的硬件可能已经有了一个设计用来与之接口的 Android 管理器。`SensorManager`就是一个很好的例子。它旨在提供来自各种不同类型传感器硬件的传感器信息。虽然您需要将一些本地代码集成到`SensorManager` HAL 中，以与特定的传感器通信，但 HAL 与`SensorManager` API 方法之间的通信过程相对简单。

### 提示

**我在哪里可以找到将自定义硬件集成到管理器的示例？**

德州仪器为它们生产和销售的各类处理器提供了一系列的**评估模块**（**EVMs**）。由于许多商业产品基于这些处理器，TI 免费提供文档和指导，介绍如何创建自定义的 HAL 代码，将通用硬件集成到 Android 管理器中。查找这些详细信息最好的地方是 TI 的 Sitara Android SDK 的文档。SDK 的网页位于[`www.ti.com/tool/androidsdk-sitara`](http://www.ti.com/tool/androidsdk-sitara)。

## 为自定义硬件创建新的管理器

如果你正在将独特的硬件集成到 Android 中，比如你在第六章《*创建一个完整的接口解决方案*》中创建的环境采样器，可能没有标准的 Android 管理器提供必要的 API 方法让应用与硬件正确通信。在这种情况下，你可以考虑创建一种新的管理器，专门处理这种独特硬件。

新的管理器可以专门针对与其交互的硬件进行定制。例如，BBB 提供了专门的硬件，允许软件与大多数现代汽车内部的计算机通信。这种功能在标准的 Android 移动设备中是不可用的，因此不存在处理此类通信的管理器。

创建一个新的管理器来处理使用此接口的具体细节，并提供自定义 API 以使用此管理器，使应用无需了解此类通信的细节。然而，以下原因应将其视为最后的手段：

+   这里没有现成的管理器代码可以作为基础。最多，你可能找到一个简单的管理器，从中复制代码作为起点。

+   必须修改 Android 构建过程以包含构建新的管理器代码。这需要将新管理器的源文件添加到 Android makefiles 中，并验证 Android 框架没有被破坏。构建 Android 是一个庞大而复杂的任务，因此对过程进行任何更改都不应轻率进行。

+   你必须设计一个适当的 API 来与新管理器接口。由于这个新的接口添加不是标准 Android API 的一部分，应用将无法包含这些 API 调用，除非你特别将它们添加到你的 Eclipse ADT 安装中。

+   你还必须增强 `android.Manifest.permission` 以包含一个或多个新的权限设置，允许应用访问新管理器的功能。作为替代方案，你可以依托现有权限，或者选择完全不用权限。

总的来说，构建一个自定义管理器是相当大的工作量，且不是胆小者所为。这个过程涉及到 Android 框架的许多不同部分，并需要所有这些部分功能的专长。如果你发现自己认为绝对需要创建一个新的管理器来通过 Android 框架正确处理你的硬件，你应该考虑跳过管理器，并使用与本例书中类似的方法：让你的应用直接使用 JNI 与硬件通信。

# 将你的项目与其他硬件结合

现在你已经考虑了如何最好地修改你的 Android 系统的软件方面，以完全集成你的定制硬件项目，让我们来看看硬件方面的事情。面包板可以很好地让你快速创建和更改你的硬件项目设计。硬件和软件共同设计是一个迭代过程，因此你可能会发现自己在开发接口软件时更改硬件设计。然而，携带面包板来展示你的硬件项目远非理想之选。

## 构建自己的原型斗篷

为什么不创建你自己的定制斗篷板项目呢？如果你为你的 Android 系统开发了完美的硬件项目，你应该考虑将其制作成独立的斗篷板。将你的项目设计成斗篷形式，可以轻松地与其他斗篷板集成。它还允许你将项目从一处移动到另一处，而不必担心干扰电路或意外断开面包板电线。

对于没有经验的人来说，创建一个专业布局的定制斗篷 PCB 是一项非常困难的任务。但是，只要你有一点焊接和规划，你仍然可以构建自己的斗篷板。Adafruit 的原型斗篷套件（产品 ID 572）是一个很好的起点。原型斗篷只不过是一个通用 PCB，用于固定那些被焊接成半永久电路的组件。如果你购买了我们在第一章中提到的 BeagleBone Black 入门包（产品 ID 703），*《Android 与 BeagleBone Black 的介绍》*，那么你已经有了原型斗篷，因为它包含在那个套件中。

![构建自己的原型斗篷](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00031.jpeg)

用于构建半永久性斗篷电路的原型斗篷套件（来源：[www.adafruit.com](http://www.adafruit.com)）

### 注意

原型斗篷还具有一个重要的优势，那就是移除了阻挡 P8/P9 连接器开口的面包板电线。最多可以同时连接四个斗篷，通过*堆叠*斗篷（通过每个斗篷上的 P8/P9 连接器通行孔将一个斗篷插入另一个斗篷）。这为你提供了将不同的斗篷组合在一起的机会，创建一个定制的 Android 系统，充分利用你所设计的定制硬件。如果面包板电线阻挡了 P8/P9 连接，其他斗篷将无法插入连接器并堆叠在 BBB 的顶部。这使得如果堆叠中最顶层的斗篷没有通行 P8/P9 连接器（像大多数 LCD 斗篷一样），就无法使用面包板设计。

## 与 Android 接口的商业斗篷

市面上有许多现成的 BBB 扩展板可供购买，与 Android 配合使用效果良好。4D Systems（[`www.4dsystems.com.au/`](http://www.4dsystems.com.au/)）提供多种不同尺寸和分辨率的 LCD 扩展板，价格合理，既有触摸屏也有非触摸屏型号。BeagleBoard Toys（[`www.beagleboardtoys.com/`](http://www.beagleboardtoys.com/)）也提供各种扩展板，如 LCD、音频和电池扩展板。通过将不同的扩展板与 BBB 结合，你可以将你的 Android 系统转变为便携式 Android 设备！

![与 Android 接口的商业扩展板](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00032.jpeg)

左侧的 4DCAPE-70T（800 x 480 像素）和右侧的 4DCAPE-43T（480 x 272 像素）4D Systems 触摸屏 LCD 扩展板（来源：[www.4dsystems.com.au](http://www.4dsystems.com.au)）

### 提示

**那么 USB 设备呢？**

其他需要考虑的硬件组件包括 USB 设备，如音频设备、鼠标、键盘、Wi-Fi 适配器、蓝牙适配器、游戏手柄和网络摄像头。由于 Linux 内核包含所有这些设备的驱动程序，你可以轻松地使用它们来扩展你的 Android 平台并开发各种创意应用。BBB 只有一个 USB 端口，但你可以将 USB 集线器连接到该端口，以支持同时使用多个 USB 设备。

你可能可以创建一个基于 Android 的手持游戏机，带有 GPIO 控制器输入和基于 SPI 或 I2C 的加速度计。或者，你可以设计一个带有触摸屏 LCD 的定制汽车控制台，从你的车辆中收集实时数据。你控制着整个平台的硬件和软件，而 Android 应用开发工具非常适合快速轻松地创建 UI。可能性是无限的！

![与 Android 接口的商业扩展板](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00033.jpeg)

左侧的 5VDC 电池和右侧的音频 CODEC CircuitCo 扩展板（来源：[www.beagleboardtoys.com](http://www.beagleboardtoys.com)）

# 探索 BBB 的其他接口

到目前为止，我们已将 BBB 的 GPIO、SPI 和 I2C 功能用于我们的接口。但这些并不是 BBB 提供的唯一接口选项。在考虑 BBB 上的 Android 项目时，您应该记住以下一些其他接口。

## 可编程实时单元

BBB 的 AM335X 处理器内嵌有一对可编程实时单元（PRU）。这些单元的时钟频率为 200 MHz，因此它们每 5 ns 执行一条指令。内核将程序加载到 PRU 中，然后指示 PRU 开始执行。PRU 与内核之间的通信通过共享内存进行。PRU 的执行与主处理器的执行完全分离，除非处理器与 PRU 之间需要协调，否则将 PRU 推向极限不会对主处理器产生性能影响。

有许多 GPIO 引脚可以通过多路复用，使它们直接受到 PRU 的控制。PRU 可以在每个指令上检查或设置这些 GPIO 的值，这意味着 PRU 控制的 GPIO 可以足够快地切换以实现复杂数字接口（如 SPI 和 I2C）的“位碰撞”实现。如果你有一块定制的硬件，并且需要实现一个与之的高速接口，使用一个或两个 PRU 是一个选项。

## 串行通信

BBB 提供了五个串行通信 UART，可以通过多路复用器连接到 P8 和 P9 连接器的引脚上。此外，还有一个第六个 UART（UART0），通过 FTDI 电缆提供串行调试输出。如果你使用 BBB 来控制大量的串行控制设备，这些 UART 是非常有用的资源。

不幸的是，这些 UART 中的几个（UART 3、4 和 5）与提供视频数据到 LCD cape 和内部 HDMI cape 的 LCD 接口总线使用的引脚冲突。由于 Android 的强大之处很大程度上来自于其用户界面，禁用 LCD 接口以接收更多 UART 通常是非常不划算的。如果你发现你绝对需要在 Android 下使用这些 UART，所有 UART 都可以使用标准的 Linux 内核串行驱动程序和现有的 NDK 库访问文件系统中的`/dev/TTYS*`文件。

## 控制器区域网络

BBB 上有两个**控制器区域网络**（**CAN**）总线。CAN 是一种串行协议，也是用于车辆接口的**车载诊断**（**OBD**）标准的五种协议之一。车辆诊断硬件和软件使用 CAN 与大多数现代汽车的主控控制器进行通信。Linux 内核中的 CAN 驱动程序将每个 CAN 总线公开为网络接口，可以通过网络套接字编程与其通信。如果你有兴趣创建一个能够与你的车辆通信的 Android 设备，比如车内的状态显示屏或手持诊断单元，CAN 总线正是你所需要的。

CAN0 总线多路复用到 P9.19 和 P9.20 引脚上，这些引脚也是 capemgr 用于发现任何连接的 cape 身份的 I2C2 总线所使用的引脚。将 CAN1 总线多路复用到 P9.24 和 P9.26 引脚可能会与 I2C1 冲突，这取决于你是如何多路复用 I2C 通道的。通常，你不能同时使用 SPI、I2C 和 CAN。

## 模数转换器

BBB 不仅限于数字通信。它还提供了一个 8 通道、12 位的**模数转换器**（**ADC**），允许 BBB 接收 0 到 1.8V 之间的模拟电压水平。这对于与真实世界的传感器交互以及许多触摸屏显示非常有用。但是，你必须非常小心，确保施加在这些引脚上的电压永远不会超过 1.8 伏，否则你会损坏 BBB。

P9.32 至 P9.40 引脚已永久与 ADC 复用，因此你可以自由地将它们用于自己的项目。目前，CircuitCo 和 4D Systems 的带触摸屏支持的 LCD 扩展板使用了 ADC 通道 4-7 进行触摸屏操作，留下了通道 0-3 供你使用。

## 脉冲宽度调制

BBB 上的 AM3359 处理器拥有一个**脉冲宽度调制**（**PWM**）子系统，用于精确控制电动机。PWM 设置向电机供电的周期和占空比，以控制其转速。PWM 子系统包含三个**增强型高分辨率脉冲宽度调制器**（**eHRPWM**）模块和一个**增强型正交编码脉冲**（**eQEP**）模块。这四个模块总共提供了八个用于驱动电机的 PWM 通道。

尽管 PWM 通常用于控制工业制造设备、机器人伺服电机和各种其他机械系统，但它也可以用来控制照明的亮度以及其他可以利用 PWM 的可变占空比来模拟全强度开关之间的功率/亮度/速度级别的任务。如果你有兴趣使用 Android 操作系统控制机械系统，PWM 绝对是 BBB 上你应该进一步探索的功能。

# 总结

在本章中，我们研究了如何将你的自定义硬件项目完全集成到 BBB 上的 Android 中。我们讨论了如何将你的自定义设备驱动直接构建到 Linux 内核中，以及如何将你的自定义 Device Tree 覆盖层直接编译到主 Device Tree 中。这样可以避免在`init.{ro.hardware}.rc`文件中包含特殊模块和加载命令的覆盖层。

我们还探讨了如何定制标准的 Android 软件框架，以包括对自定义硬件项目的支持。现有的 Android 管理器可以被扩展以支持自定义硬件。

我们探讨了如何使用 Proto Cape 使你的自定义硬件设计半永久化。这可以避免在移动项目时意外断开面包板电线。它还通过避免面包板电线阻塞 P8/P9 连接器，使得与商业 BBB 扩展板的集成更加容易。我们还提到，有许多类型的 USB 设备也得到 Android 的支持，在考虑新项目时值得探索。

最后，我们探索了一些本书早期章节示例中未涵盖的其他 BBB 接口。BBB 的 PRU、串行 UART、CAN 总线、ADC 和 PWM 子系统都提供了额外的功能，以便与外部世界接口。
