# UDOO 入门手册（二）

> 原文：[`zh.annas-archive.org/md5/4AF381CD21F1B858B50BF52774AC99BB`](https://zh.annas-archive.org/md5/4AF381CD21F1B858B50BF52774AC99BB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：管理与物理组件的交互

电子设备改变了我们的生活。我们被许多看不见的物体所包围，它们收集并最终计算环境数据。正如我们在上一章所看到的，这些设备使用传感器来获取信息，并且我们可以在日常生活中找到它们，例如在我们的汽车中，当我们穿过超市的滑动门时，或者当我们回到家时。

我们可以从这些事物中汲取灵感，构建能够对环境和周围的人做出反应的惊人的物理应用。然而，如果我们的项目需要直接的与人交互，我们可能需要使用物理组件来管理这种交互。

本章的目标是构建一个使用内置 Android API 管理网络流的网络收音机，同时所有交互都由物理组件管理，就像旧式收音机一样。

在本章中，我们将涵盖以下主题：

+   管理用户交互

+   使用物理交互构建网络收音机

+   使用 Arduino 发送多个数据

+   编写用于音频流的 Android 应用程序

# 管理用户交互

区分交互式原型的其中一个方面是能够对用户的任何操作做出反应。正如我们在上一章所看到的，传感器是实现这一重要目标的最重要构建块之一。然而，有时我们希望提供一个物理交互，让用户能够通过双手改变应用程序的行为，尽管存在传感器。这些仍然广泛使用部分是简单的**机械**或**电子**组件，它们将模拟动作转换为微控制器可以用来改变程序流程的数字值。有许多我们可以用来与设备交互的组件：**按钮**、**开关按钮**、**操纵杆**、**扭钮**、**踏板**和**杠杆**，这些只是这类组件的例子。

扭钮是我们用来调整一些原型配置的组件。实际上，我们可以创建一个维护控制台，通过改变某些设备常数以避免新草图的重编译和上传阶段。在其他时候，扭钮用于直接操作，其使用是用户交互活动的积极部分。扭钮的常见用途与电器设备相关，例如音频设备中的音量控制。

另一个例子可能是与火星车有关，当我们希望为用户提供直接控制而不是依靠机器人自身的人工智能时。在这种情况下，我们可以使用一个按钮来方便地激活停止动作并切换到手动模式。例如，我们可以提供一个操纵杆，用于控制火星车的移动。

### 提示

按钮的一个使用例子与停止微控制器或原型所做的任何动作相关。这种按钮的使用称为**紧急停止**，在许多全自动且配备有活动部件的 DIY 项目中都会用到。

所有这些元素都有两个基本组件：**开关**和**电位计**。按钮是机械开关的好例子，它们可以关闭或打开电路，并通过微控制器引脚控制电流流。这样，我们可以根据检测到的电压激活电路的特定功能，就像在第三章，*测试您的物理应用*中所做的那样。

相反，电位计是电子元件，更像是电阻器。电子部分由三个终端腿组成，我们可以用不同的方式使用它们来改变电位计的目的。实际上，如果我们将一端和中间腿连接到一个组件，它就像一个**可变电阻器**。另一方面，如果我们使用所有三个终端，它就像一个可调节的**分压电路**。我们可以从一个方向转到另一个方向的电位计的*轴*，用于改变电阻器或分压电路的值。电位计应用的好例子有旋钮、操纵杆和吉他踏板。

# 带物理交互的构建网络收音机

微控制器并非为复杂工作而设计，因此我们需要小心地将项目的需求分配到正确的环境中。对于网络收音机，我们可以使用微控制器读取旋钮和开关，让 Android API 和 UDOO 强大的 CPU 处理其余工作。这将防止 Android 在读取硬件时分心，并防止微控制器因网络流和播放的复杂性而过载。

我们原型的第一部分是构建一个电路并编写一个草图，从两个电位计和一个按钮收集值：

+   我们使用第一个电位计来更改活动电台并增加或减少音量

+   我们使用物理按钮来控制收音机的播放

这样，我们就移除了所有通过 Android 用户界面进行的交互。

作为第一步，拿两个电位计并将它们连接到板上，这样我们就可以实现以下电路：

![带物理交互的构建网络收音机](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_05_01.jpg)

按照下面的步骤将电路连接到电位计，如前面的原理图所示：

1.  在你的面包板右侧放置两个电位计，因为我们需要在左侧的自由插槽中使用按钮。

1.  将 UDOO +3.3V 引脚连接到电源总线的正线。确保不要连接+5V 电源引脚，因为未来连接时可能会损坏模拟输入引脚。

1.  将 UDOO 地线连接到电源总线的负线。

1.  将第一个电位计的左端子连接到电源总线的负线。

    ### 提示

    电位计就像电阻一样，如果你连接了错误的正极端子，不会有任何区别。唯一的副作用是检测到的值将从[0-1023]范围变为[1023-0]。如果你注意到这一点，*请反转这些连接*。

1.  将第一个电位计的右端子连接到电源总线的正线。

1.  将中间端子连接到模拟输入 A0。

1.  对第二个电位计重复步骤 4、5、6，并将其中间端子连接到模拟输入 A1。

通过这个电路，我们使用两个电位计作为电压分压器，当我们转动轴时，微控制器注意到电压输出的变化，并将这个值转换成数值范围[0-1023]。这个电路与之前章节中构建的光传感器电路非常相似，但由于电位计已经在其包装内包含了一个电阻，我们不需要任何其他电子组件来保持其工作。

现在我们需要一个按钮来开始和停止播放。我们需要在面包板的左侧添加组件，并按以下方式连接到 UDOOboard：

![使用物理交互构建网络收音机](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_05_02.jpg)

按照给定的步骤连接组件，如前图所示：

1.  将按钮的左端子连接到电源总线的正线。

1.  使用 10 KOhm 电阻将右端子连接到电源总线的负线。

1.  将右端子连接到 UDOOboard 的 12 号引脚。

通过这个电路，我们可以使用 UDOOboard 的 12 号引脚读取按钮的值；当按下按钮时，我们可以改变微控制器的内部状态。

既然我们已经有了所有必需组件的电路，我们就必须开始一个新的草图，并准备一个函数来收集所有数据。草图的目标是准备一个包含*播放状态*、*音量*和*电台*的有序值的**三元组**。这种方法简化了稍后与 Android 应用程序通信时的工作。我们可以按照以下方式开始编写新草图：

1.  在草图顶部定义连接：

    ```kt
    #define RADIO_POLL_PERIOD 100
    #define PLAY_BUTTON 12
    #define KNOB_VOLUME A0
    #define KNOB_TUNER A1
    ```

    我们使用 12 号引脚作为播放按钮，A0 输入作为音量，A1 输入来切换当前电台。在这个项目中，我们设置了一个 100 毫秒的轮询时间，这对于物理组件和 Android 应用程序之间的快速交互是必需的。

1.  在之前的声明后添加以下变量：

    ```kt
    boolean playback = true;
    int buttonRead = LOW;
    int previousRead = LOW;
    int tuner = 0;
    int volume = 0;
    ```

    我们使用一个播放变量作为简单的状态指示器，以便草图知道收音机是否正在播放。由于我们正在构建一个依赖于物理交互的收音机，因此草图中的设备状态被认为是整个应用程序的*真实来源*，Android 应该信任这些值。我们还定义了其他变量来存储按钮和两个电位计的读数。

1.  在`setup()`函数中添加引脚模式，并打开串行通信：

    ```kt
    void setup() {
      pinMode(PLAY_BUTTON, INPUT);
      Serial.begin(115200);
    }
    ```

1.  在草图的底部创建一个`readData()`函数，在其中检测用户从物理组件的输入：

    ```kt
    void readData() {
      buttonRead = digitalRead(PLAY_BUTTON);
      if (buttonRead == HIGH && previousRead != buttonRead) {
        playback = !playback;
      }
      previousRead = buttonRead;
      tuner = analogRead(KNOB_TUNER);
      volume = analogRead(KNOB_VOLUME);
    }
    ```

    在第一部分，我们将按钮的值赋给`buttonRead`变量，以检查它是否被按下。同时，我们还将最后一次检测到的值存储在`previousRead`变量中，因为我们希望在连续读取时避免状态错误变化。这样，如果用户按住按钮，只会发生一次状态变化。

    在最后几行，我们进行`analogRead`调用，从两个电位计收集数据。

1.  在主`loop()`函数内调用`readData()`函数，并按以下方式打印收集的值：

    ```kt
    void loop() {
      readData();
      Serial.print("Playing music: ");
      Serial.println(playback);
      Serial.print("Radio station: ");
      Serial.println(tuner);
      Serial.print("Volume: ");
      Serial.println(volume);
      delay(RADIO_POLL_PERIOD);
    }
    ```

现在，我们可以将草图上传到我们的电路板上，并打开**串行监视器**，开始玩转旋钮和播放按钮。以下是预期输出的一个示例：

![使用物理交互构建网络收音机](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_05_03.jpg)

## 在发送之前规范化收集的数据

如我们所见，如果我们转动电位计的轴或按下播放按钮，我们的值会立即改变。这是一个非常好的起点，但现在我们需要转换这些数据，以便它们能被 Android 应用程序轻松使用。

因为我们想要管理五个广播电台，草图应该将调谐器的读数映射到[0-4]范围内的值。我们将在[0-1023]范围内创建固定间隔，这样当我们转动轴并通过一个间隔时，应更新活动的电台。为了实现这种映射，我们需要遵循以下步骤：

1.  在草图的顶部，添加突出显示的声明：

    ```kt
    #define KNOB_TUNER A1
    #define STATIONS 5
    #define MAX_ANALOG_READ 1024.0
    const float tunerInterval = MAX_ANALOG_READ / STATIONS;
    boolean playback = true;
    ```

    我们将管理的电台数量定义为`5`，并设置最大模拟读取值。这样，我们可以重用上面的类似对象的宏来定义`tunerInterval`常数，以将读数映射到正确的间隔。

1.  在草图的底部添加`mapStations()`函数：

    ```kt
    int mapStations(int analogValue) {
      int currentStation = analogValue / tunerInterval;
    }
    ```

    为了找到`currentStation`变量，我们将模拟读取值除以调谐器间隔。这样，我们可以确保返回的值被限制在[0-4]范围内。

使用前面的映射函数不足以让我们的收音机工作。另一个必要的步骤是转换音量值，因为 Android 使用[0.0-1.0]范围内的浮点数。因此，我们应该通过以下步骤规范化音量旋钮：

1.  在`mapStations()`函数下面添加此功能：

    ```kt
    float normalizeVolume(int analogValue) {
      return analogValue / MAX_ANALOG_READ;
    }
    ```

1.  更改主`loop()`函数，如下所示，以便我们可以检查是否所有值都正确转换：

    ```kt
    void loop() {
      readData();
      Serial.print("Playing music: ");
      Serial.println(playback);
      Serial.print("Radio station: ");
      Serial.println(mapStations(tuner));
      Serial.print("Volume: ");
      Serial.println(normalizeVolume(volume));
      delay(RADIO_POLL_PERIOD);
    }
    ```

1.  上传新的草图以查看以下截图显示的结果：![在发送前规范化收集的数据](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_05_04.jpg)

    ### 注意

    通过前面的步骤，我们从物理输入设备收集数据，并转换这些值以从旋钮计算当前的电台和收音机音量。然而，我们需要在 Android 应用程序中也放置这个逻辑，因为它应该为每个可能的电台映射相关的网络流媒体 URL。这意味着相同的逻辑被复制，这不是一个好方法，特别是如果我们将来需要添加新的频道。在这种情况下，我们的代码必须在两个应用程序中更改，并且我们应始终避免那些*容易出错*的情况。一个好方法是只使用微控制器报告输入，并让 Android 应用程序管理和转换接收到的原始数据。我们仅在本书的范围内使用这种方法，以帮助您更熟悉草图代码。

## 使用 Arduino 发送多个数据

在第四章《*使用传感器聆听环境*》中，我们需要发送由微控制器计算的一个字节。然而，在大多数常见情况下，我们需要从不同的传感器或物理组件读取数据，并且可能需要一次性将它们发送回 Android。在这个原型中，我们应该关注这一需求，因为微控制器必须读取所有三个值，并且只能通过一次 ADK 写入将它们发送回去。一个简单的方法是构建一个表示我们三元组的字符串，并使用逗号分隔这些值，格式为`<playback>,<volume>,<station>`。通过这种表示，我们得到以下值：

```kt
0,0.332768,2
1,0.951197,4
```

然后，我们可以在 ADK 缓冲区中写入收音机状态的*序列化*表示，并在 Android 应用程序中进行*反序列化*处理。

### 提示

我们可能会考虑实施或使用更复杂的通信协议，以将通用数据从 Arduino 传输到 Android，但我们应该始终牢记，在开始时，每个好主意都必须遵循**KISS 原则**：**保持简单**，**傻瓜**（一个由美国海军在 1960 年提出的设计原则）。因为软件越简单，它就越可能运行良好。

我们需要在草图的顶部编写配件描述符，如下所示的建议代码片段：

```kt
#include <adk.h>
#define BUFFSIZE 128
char accessoryName[] = "Web radio";
char manufacturer[] = "Example, Inc.";
char model[] = "WebRadio";
char versionNumber[] = "0.1.0";
char serialNumber[] = "1";
char url[] = "http://www.example.com";
uint8_t buffer[BUFFSIZE];
USBHost Usb;
ADK adk(&Usb, manufacturer, model, accessoryName, versionNumber, url, serialNumber);
```

我们还需要一个用于保存三元组的第二个缓冲区；我们可以在 ADK 缓冲区变量之前添加其声明，如下所示：

```kt
char triple[BUFFSIZE];
uint8_t buffer[BUFFSIZE];
```

在草图的底部，添加以下函数以在 ADK 缓冲区中写入三元组：

```kt
void writeBuffer(int playback, float volume, int station) {
  sprintf(triple, "%f,%f,%f", (float) playback, normalizeVolume(volume), (float) mapStations(station));
  memcpy(buffer, triple, BUFFSIZE);
}
```

`writeBuffer()`函数期望三个用于构建三元组的参数。为此，我们使用`sprintf()`函数将这些值写入中间`triple`缓冲区。在`sprintf()`函数调用中，我们还使用`normalizeVolume()`和`mapStations()`函数获取转换后的值。然后我们使用`memcpy()`函数将`triple`变量写入 ADK `buffer`。

### 注意

我们需要这个额外的步骤，因为我们不能将`triple`变量写入 ADK `buffer`中。`adk.write()`函数期望一个`unsigned char*`类型，而`triple`是`char*`类型。

既然 ADK 缓冲区包含了序列化的数据，我们就必须移除所有的`Serial`调用，并按以下方式重写主`loop()`函数：

```kt
void loop() {
  Usb.Task();
  if (adk.isReady()) {
    readData();
    writeBuffer(playback, volume, tuner);
    adk.write(BUFFSIZE, buffer);
  }
  delay(RADIO_POLL_PERIOD);
}
```

当 ADK 准备就绪时，我们从推按键和两个电位计中读取数据，然后将这些值序列化到一个三元组中，该三元组将被写入 ADK 输出缓冲区。一切准备就绪后，我们将记录的输入发送回 Android。

我们现在可以更新我们的草图，并使用 Android 应用程序完成原型。

# 从 Android 应用程序中流式传输音频

Android 操作系统提供了一组丰富的 UI 组件，这是所有物理应用的重要构建块。它们都是针对手机或平板交互的，这是一项杰出的改进，因为用户已经知道如何使用它们。然而，Android 不仅仅是一组 UI 组件，因为它允许许多 API 来实现常规任务。在我们的案例中，我们希望一个物理应用能够与 Web 服务交互，以打开和播放音频流。

如果没有 i.MX6 处理器和 Android 操作系统，这项任务将不可能轻松实现，但在我们的情况下，UDOO 开发板提供了我们所需要的一切。

## 设计 Android 用户界面

在 Android Studio 中，启动一个名为**WebRadio**的新应用，使用**Android API 19**。在引导过程中，选择一个名为**Radio**的**空白活动**。

我们的首要目标是改变默认布局，以一个简单但花哨的界面替代。主布局必须显示当前激活的广播电台，并提供不同的信息，如可选的图片——频道名称以及描述。在编写 Android 绘制用户界面所需的 XML 代码之前，我们应该规划工作以检测所需的组件。在下面的截图中，我们可以查看提供所有必需元素的用户界面草图：

![设计 Android 用户界面](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_05_05.jpg)

上面的布局包括一个数字标记，定义了组件创建的顺序。根据此布局，我们应该按照以下顺序提供三个不同的视图：

1.  作为第一步，我们应该创建一个不同颜色的背景框架，以提供一个块，我们将把所有其他组件放入其中。

1.  尽管这是可选的，但我们可以准备一个框，如果可用的话，将用于显示电台频道图片。

1.  最后一个块包含两个不同的文本区域，第一个代表频道名称，而另一个代表频道描述。

使用这种布局设计，我们应该按照以下步骤继续操作，替换标准主题：

1.  在 `res/values/dimens.xml` 资源文件中，添加以下定义，为我们提供一些组件的尺寸，如背景框架高度和字体大小：

    ```kt
    <resources>
      <dimen name="activity_horizontal_margin">16dp</dimen>
      <dimen name="activity_vertical_margin">16dp</dimen>
      <dimen name="activity_frame_height">220dp</dimen>
      <dimen name="activity_image_square">180dp</dimen>
      <dimen name="layout_padding">50dp</dimen>
      <dimen name="title_size">40sp</dimen>
      <dimen name="description_size">25sp</dimen>
    </resources>
    ```

1.  在 `res/values/styles.xml` 资源文件中，添加背景框架和文本元素使用的以下颜色：

    ```kt
    <resources>
      <color name="picton_blue">#33B5E5</color>
      <color name="white">#FFFFFF</color>
      <style name="AppTheme" parent="Theme.AppCompat.Light.DarkActionBar">
      </style>
    </resources>
    ```

1.  在 `res/layout/` 下的 `activity_radio.xml` 文件中，用以下 `FrameLayout` 替换 `RelativeLayout` 以实现背景框架：

    ```kt
    <FrameLayout 

      android:layout_width="match_parent"
      android:layout_height="@dimen/activity_frame_height"
      android:paddingLeft="@dimen/activity_horizontal_margin"
      android:paddingRight="@dimen/activity_horizontal_margin"
      android:paddingTop="@dimen/activity_vertical_margin"
      android:paddingBottom="@dimen/activity_vertical_margin"
      android:background="@color/picton_blue"
      tools:context=".Radio">
    </FrameLayout>

    ```

    我们使用 `FrameLayout` 创建一个区域，该区域以定义的高度和背景色容纳所有其他组件。

1.  在上述 `FrameLayout` 参数中创建一个 `LinearLayout`：

    ```kt
    <LinearLayout
      android:orientation="horizontal"
      android:layout_width="match_parent"
      android:layout_height="match_parent">

        <ImageView
          android:id="@+id/radio_image"
          android:src="img/ic_launcher"
          android:layout_height="@dimen/activity_image_square"
          android:layout_width=
            "@dimen/activity_image_square" />

        <LinearLayout
          android:orientation="vertical"
          android:layout_marginLeft="@dimen/layout_padding"
          android:layout_width="match_parent"
          android:layout_height="match_parent">
        </LinearLayout>
    </LinearLayout>
    ```

    第一个 `LinearLayout` 将包含根据活动频道而变化的 `radio_image` `ImageView`。第二个 `LinearLayout` 用于容纳电台名称和描述。

1.  在第二个 `LinearLayout` 中添加以下视图：

    ```kt
    <TextView
      android:id="@+id/radio_name"
      android:text="Radio name"
      android:textColor="@color/white"
      android:textSize="@dimen/title_size"
      android:layout_width="wrap_content"
      android:layout_height="wrap_content" />

    <TextView
      android:id="@+id/radio_description"
      android:text="Description"
      android:textSize="@dimen/description_size"
      android:layout_width="wrap_content"
      android:layout_height="wrap_content" />
    ```

根据之前定义的样式，以下是获得的布局：

![设计 Android 用户界面](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_05_06.jpg)

在我们继续逻辑实现之前，我们必须在 `onCreate()` 回调中通过以下步骤获取所有视图引用：

1.  在 `Radio` 类的顶部添加以下声明：

    ```kt
    private TextView mRadioName;
    private TextView mRadioDescription;
    private ImageView mRadioImage;
    ```

1.  在 `onCreate()` 回调的底部，添加高亮代码：

    ```kt
    setContentView(R.layout.activity_radio);
    mRadioName = (TextView) findViewById(R.id.radio_name);
    mRadioDescription = (TextView) findViewById(R.id.radio_description);
    mRadioImage = (ImageView) findViewById(R.id.radio_image);

    ```

现在布局已完成，我们可以继续进行 ADK 配置。

## 设置 ADK 工具包

在我们开始网络电台实现之前，我们首先应该像上一章一样配置 *ADKToolkit*。为了拥有可工作的 ADK 配置，请按照以下步骤操作：

1.  在 `app` 下的 `build.gradle` 文件中添加 *ADKToolkit* 库依赖。

1.  同步你的 Gradle 配置。

1.  在 `res/xml/` 下创建配件过滤器文件 `usb_accessory_filter.xml`，使用以下代码：

    ```kt
    <resources>
      <usb-accessory
       version="0.1.0"
       model="WebRadio"
       manufacturer="Example, Inc."/>
    </resources>
    ```

1.  在 `AndroidManifest.xml` 文件中添加 *USB accessory support* 选项要求和 *USB accessory intent filter* 选项。

1.  在 `Radio.java` 类文件中，在类的顶部声明 `AdkManager` 对象。

1.  在 `Radio` 活动类的 `onCreate` 方法中添加 `AdkManager` 初始化。

1.  重写 `onPause()` 和 `onResume()` 回调，根据活动生命周期来启动和停止 ADK 连接。

    ### 提示

    每次我们开始一个新项目时，都应该使用上述清单。最好将这些步骤写下来，确保我们的项目始终以此 ADK 配置开始。

1.  作为初始配置的最后一步，我们需要添加互联网访问权限，因为我们将使用网络流。在你的`AndroidManifest.xml`文件的 manifest 标签内添加以下权限：

    ```kt
    <uses-permission android:name="android.permission.INTERNET" />
    ```

## 更换网络电台

下一步是编写必要的 Android 代码以播放和停止配置的电台。我们需要正式化电台对象和一个实用程序类，该类抽象了内置媒体播放器的相同功能。以下是所需类的使用清单：

+   `Station`：正式定义音频频道，并包括标题、描述和电台图片，以及启动远程播放所需的流媒体 URL

+   `RadioManager`：在初始化期间配置所有可用的电台，并将所有管理播放和频道切换的通用方法抽象出来

我们从可以通过以下步骤实现的`Station`类开始：

1.  在我们的命名空间内创建一个名为`streaming`的新 Java 包。

1.  在新创建的 Java 包中创建`Station`类，并添加以下声明和类构造函数：

    ```kt
    private final static String STREAMING_BASE_URL = "https://streaming.jamendo.com/";
    private String title;
    private String description;
    private int imageId;
    public Station(String title, String description, int imageId) {
      this.title = title;
      this.description = description;
      this.imageId = imageId;
    }
    ```

    我们定义了我们将用于构建频道流媒体 URL 的第一部分。在这种情况下，我们将使用提供许多在**Creative Commons**许可下发布的音乐频道的**Jamendo**服务。如果你想获取更多信息，可以查看服务网站：

    [Jamendo 网站](https://www.jamendo.com)

    我们将使用的其他属性是电台的`title`和`description`属性以及 Android 资源标识符。

1.  在类的底部，以下获取器用于检索实例属性：

    ```kt
    public String getTitle() {
      return title;
    }
    public String getDescription() {
      return description;
    }
    public int getImageId() {
      return imageId;
    }
    public String getStreamUrl() {
      return STREAMING_BASE_URL + title;
    }
    ```

    在`getStreamUrl()`方法中，我们使用带有电台名称的基础 URL 来查找正确的音频流。

    ### 提示

    这个字符串连接与 Jamendo 服务的工作方式有关。如果你使用另一个服务或不想在 URL 构建时使用标题属性，你应该更改这个方法。

既然我们已经有了正式的`Station`类表示，我们需要定义一个能够管理 Android 播放的类。我们通过以下步骤实现`RadioManager`类：

1.  在`streaming`包中，创建`RadioManager`类，并在开始处添加以下声明：

    ```kt
    private static ArrayList<Station> mChannels;
    private static MediaPlayer mMediaPlayer;
    private static int mPlayback;
    private static int mIndex;
    private static Station mActiveStation;
    ```

    我们使用 Android 高级`MediaPlayer`对象来管理远程流媒体；我们使用一些状态变量，如当前活动电台及其数组索引和播放状态。我们将在`RadioManager`类初始化期间填充`mChannels` `ArrayList`对象，它将托管所有可用的音乐频道。

1.  在类的底部添加初始化方法，如下所示：

    ```kt
    public static void initialize() {
      // Prepare all stations object
      mChannels = new ArrayList();
      mChannels.add(new Station("JamPop", "Pop", R.drawable.ic_launcher));
      mChannels.add(new Station("JamClassical", "Classical", R.drawable.ic_launcher));
      mChannels.add(new Station("JamJazz", "Jazz", R.drawable.ic_launcher));
      mChannels.add(new Station("JamElectro", "Electronic", R.drawable.ic_launcher));
      mChannels.add(new Station("JamRock", "Rock", R.drawable.ic_launcher));
      // Initializes the MediaPlayer with listeners
      mMediaPlayer = new MediaPlayer();
      mMediaPlayer.setAudioStreamType(AudioManager.STREAM_MUSIC);
      mMediaPlayer.setOnPreparedListener(new MediaPlayer.OnPreparedListener() {
        @Override
        public void onPrepared(MediaPlayer mediaPlayer) {
          mediaPlayer.start();
        }
      });
    }
    ```

    在第一部分，我们根据之前的 `Station` 构造函数配置所有可用频道的列表。我们配置 `MediaPlayer` 对象，以便在 prepare 过程完成后立即开始网络流。

    ### 注意

    你可以在以下 URL 查找更多关于 Android `MediaPlayer` 类如何工作的信息：

    [`developer.android.com/reference/android/media/MediaPlayer.html`](http://developer.android.com/reference/android/media/MediaPlayer.html)。

1.  添加以下方法，以抽象播放和停止功能，防止代码重复：

    ```kt
    private static void stop() {
      mMediaPlayer.reset();
    }
    private static void play() {
      try {
        mMediaPlayer.setDataSource(mActiveStation.getStreamUrl());
        mMediaPlayer.prepareAsync();
      }
      catch (IOException e) {
        // noop
      }
    }
    ```

    当播放器停止时，我们必须重置媒体播放器对象，因为我们可能需要立即设置另一个数据源。`play` 方法设置当前激活频道的流媒体 URL 并开始一个非阻塞的 prepare 任务。

1.  添加以下公共方法，该方法改变播放状态：

    ```kt
    public static void playback(int value) {
      // If the playback status has changed
      if (value != mPlayback) {
        // Play or stop the playback
        if (value == 0) {
          stop();
        }
        else {
          play();
        }
        mPlayback = value;
      }
    }
    ```

    通过 ADK 的草图，我们的应用程序每隔 100 毫秒就会收到连续的数据，这提高了用户界面的响应性。然而，我们不想多次重复相同的命令，所以我们只有在收到的值与存储的值不同时才会执行操作。在第二部分，我们根据给定的参数选择开始或播放当前流。

1.  作为最后一步，我们需要一个方法来更改激活的频道。在类的底部添加以下代码：

    ```kt
    public static Station changeStation(int stationId) {
      Station station = null;
      if (stationId != mIndex) {
        mIndex = stationId;
        // Set the current station
        mActiveStation = mChannels.get(mIndex);
        station = mActiveStation;
        stop();
        if (mPlayback == 1) {
          play();
        }
      }
      return station;
    }
    ```

    正如我们之前所做的，如果收到的值与我们当前播放的值相同，我们避免更改频道。然后，我们更新当前频道并停止最后的流。这样，如果我们处于播放状态，我们可以安全地播放新的电台流。在任何情况下，我们返回选择的 `Station` 实例，如果频道没有变化则返回 `null`。

## 从物理设备读取输入

正如我们在上一章所做的，我们需要准备我们的应用程序，以使 ADK 缓冲区中用户输入的连续读取变得可用。正如之前所做，我们将创建一个 Java 接口，公开所需的方法以更新用户界面。我们可以通过以下步骤实现这一点：

1.  创建一个名为 `OnDataChanges` 的新 Java 接口，并添加以下方法：

    ```kt
    public interface OnDataChanges {
      void updateStation(Station station);
    }
    ```

1.  让 `Radio` 类通过高亮代码实现前面的接口：

    ```kt
    public class Radio extends ActionBarActivity implements OnDataChanges {
    ```

1.  在类的末尾实现接口代码，以更新 Android 用户界面：

    ```kt
    @Override
    public void updateStation(Station station) {
      mRadioName.setText(station.getTitle());
      mRadioDescription.setText(station.getDescription());
      mRadioImage.setImageResource(station.getImageId());
    }
    ```

    在这部分，我们根据 `station` 实例属性简单地更新所有视图。

最后一个必要的步骤是实现我们的计划线程，从微控制器读取处理过的数据，并一起更新 `MediaPlayer` 类的流和 Android 用户界面。要完成这最后一个构建块，请执行以下步骤：

1.  在你的命名空间中创建一个名为 `adk` 的新包。

1.  在 `adk` 包中，添加一个名为 `DataReader` 的新类。

1.  在类的顶部，添加以下声明：

    ```kt
    private final static int INPUT_POLLING = 100;
    private final static int STATION_UPDATE = 0;
    private AdkManager mAdkManager;
    private OnDataChanges mCaller;
    private ScheduledExecutorService mScheduler;
    private Handler mMainLoop;
    ```

    与前一章一样，我们定义主线程处理器使用的轮询时间和消息类型。我们还存储了`AdkManager`参数和调用活动的引用，分别用于 ADK 读取方法和`updateStation`函数的回调。然后我们定义了`ExecutorService`方法的实现以及主线程`Handler`。

1.  实现主线程从后台线程接收到新消息时设置消息处理器的`DataReader`构造函数：

    ```kt
    public DataReader(AdkManager adkManager, OnDataChanges caller) {
      this.mAdkManager = adkManager;
      this.mCaller = caller;
      mMainLoop = new Handler(Looper.getMainLooper()) {
        @Override
        public void handleMessage(Message message) {
          switch (message.what) {
            case STATION_UPDATE:
              mCaller.updateStation((Station) message.obj);
              break;
          }
        }
      };
    }
    ```

    我们存储`AdkManager`和`caller`活动的引用，然后设置一个附加到应用程序主循环的`Handler`。`handleMessage`回调检查消息代码以识别`STATION_UPDATE`消息。在这种情况下，我们调用`updateStation`方法并传递附加的对象。

1.  在`DataReader`类的底部，添加以下私有类，实现`Runnable`接口以读取和管理物理输入设备：

    ```kt
    private class InputThread implements Runnable {
      @Override
      public void run() {
        // Read from ADK
        AdkMessage response = mAdkManager.read();
        // Parse the response
        String[] collectedInputs = response.getString().split(",");
        int playback = (int) Float.parseFloat(collectedInputs[0]);
        int station = (int) Float.parseFloat(collectedInputs[2]);
        // Start radio and get the changed station
        RadioManager.playback(playback);
        Station currentStation = RadioManager.changeStation(station);
        // Updated station back to the main thread
        if (currentStation != null) {
          Message message = mMainLoop.obtainMessage(STATION_UPDATE, currentStation);
          message.sendToTarget();
        }
      }
    }
    ```

    线程启动时，我们使用`AdkManager`方法读取用户输入。然后我们从响应中获取原始字符串，并使用分割方法反序列化接收到的三元组。第一个位置指的是播放状态，我们在`RadioManager`类中使用它来启动或停止播放。第三个位置是激活的频道，我们将其传递给`changeStation`方法。根据之前的实现，如果`currentStation`变量没有改变，我们避免将消息发布到主线程，以防止无用的界面重绘。

1.  向`DataReader`类添加一个方法，以定期生成短生命周期的线程来启动调度程序：

    ```kt
    public void start() {
      // Initialize threads
      InputThread thread = new InputThread();
      // Should start over and over while publishing results
      mScheduler = Executors.newSingleThreadScheduledExecutor();
      mScheduler.scheduleAtFixedRate(thread, 0, INPUT_POLLING, TimeUnit.MILLISECONDS);
    }
    ```

    与上一个项目一样，我们使用一个调度程序，每次在`INPUT_POLLING`变量毫秒时生成一个单独的`InputThread`参数。

1.  在类的底部添加停止方法，通过执行器的`shutdown`方法停止调度程序生成新线程：

    ```kt
    public void stop() {
      mScheduler.shutdown();
    }
    ```

1.  现在，我们应该回到`Radio`类中，在活动生命周期内启动和停止调度程序。在`Radio`类的顶部添加`DataReader`方法声明：

    ```kt
    private AdkManager mAdkManager;
    private DataReader mReader;

    ```

1.  在活动创建时初始化`RadioManager`类和`DataReader`实例，通过以下高亮代码，你应该将其添加到`onCreate()`回调的底部：

    ```kt
    mRadioImage = (ImageView) findViewById(R.id.radio_image);
    RadioManager.initialize();
    mAdkManager = new AdkManager(this);
    mReader = new DataReader(mAdkManager, this);

    ```

1.  如高亮代码所示，在`onResume()`和`onPause()`活动的回调中启动和停止读取调度程序：

    ```kt
    @Override
    protected void onPause() {
      super.onPause();
      mReader.stop();
      mAdkManager.close();
    }

    @Override
    protected void onResume() {
      super.onResume();
      mAdkManager.open();
      mReader.start();
    }
    ```

完成这些步骤后，广播电台就完成了，我们可以将 Android 应用程序上传到 UDO0 板，并通过旋钮和按钮开始播放。

### 注意

因为我们没有处理网络错误，请确保 UDO0 已连接到互联网，并且你正在使用以太网或 Wi-Fi 网络适配器，否则应用程序将无法工作。

## 管理音频音量

在我们可以发布第一个广播原型之前，我们应该从 Android 应用程序管理音量旋钮。这部分非常简单，这要感谢`MediaPlayer`方法的 API，因为它公开了一个公共方法来改变激活流的音量。为了用音量管理器改进我们的项目，我们需要添加以下代码片段：

1.  在`RadioManager`类中，请在类顶部添加高亮的声明：

    ```kt
    private static Station mActiveStation;
    private static float mVolume = 1.0f;

    ```

1.  在`RadioManager`类的底部，添加以下公共方法：

    ```kt
    public static void setVolume(float volume) {
      if (Math.abs(mVolume - volume) > 0.05) {
        mVolume = volume;
        mMediaPlayer.setVolume(volume, volume);
      }
    }
    ```

    `setVolume`方法预期接收来自 Arduino 的浮点数作为参数，我们用它来改变`mMediaPlayer`实例的音量。然而，由于我们不希望因为微小的变化而改变音量，因此我们放弃了所有与之前记录的输入差异不大的请求。

1.  在`DataReader`类中编写的`InputThread`实现中添加音量解析和`setVolume`函数调用：

    ```kt
    float volume = Float.parseFloat(collectedInputs[1]);
    int station = (int) Float.parseFloat(collectedInputs [2]);
    RadioManager.playback(playback);
    RadioManager.setVolume(volume);

    ```

有了这最后一块，网络广播就完成了，我们可以继续进行最后的部署。现在，我们的用户可以使用旋钮和按钮与原型互动，控制应用程序的各个方面。

# 改进原型

在进一步讨论其他原型之前，我们应该考虑当发生一些意外事件时，我们如何改进我们的设备。一个好的起点是考虑错误处理，特别是当 Android 应用程序停止从外设接收数据时会发生什么。有许多方法可以防止错误操作，一个好的解决方案是在 Android 应用程序中包含一个默认行为，这些紧急情况下原型应该遵循。

我们本可以使用另一个周期性定时器，每次执行时增加一个变量。当`InputThread`实例完成一次成功的读取后，它应该重置上述变量。通过这种方式，我们可以监控停止接收用户输入的时间，根据这个时间，我们可能决定改变应用程序的行为。通过这个变量，例如，如果外设停止提供用户输入，我们可以停止广播播放，或者稍微降低音量。

关键点是，我们应始终为失败和成功设计我们的原型。大多数*如果发生*的问题在前端很容易融入，但后来很难添加。

# 总结

在本章中，您学习了当需要人机交互时，如何提高我们原型的质量。我们探索了一些常见的物理组件，它们可以用来改变或控制 Android 应用程序。通过强大的 Android API，我们构建了一个能够执行复杂任务如网络流传输的网络广播。

在第一部分，我们使用两个电位计和一个按钮构建了所需的电路。当通过串行监视器检查返回的值时，我们发现它们在这种格式下并不太有用，因此我们编写了映射和归一化函数。

我们继续为 Android 应用程序提供新的布局，但我们避免通过用户界面添加任何交互。我们编写了一个类来抽象化与内置媒体播放器的所有可能交互，这样我们可以轻松地在应用的任何部分控制这个组件。事实上，我们在后台任务中使用它，每当它读取用户输入时，它会立即改变收音机的状态。通过这种方式，我们启用了按钮来启动和停止播放，以及两个电位器来改变活动电台和音乐音量。

在下一章中，我们开始讨论家居自动化。我们从零开始设计一个新的原型，能够使用传感器数值和用户设置的组合来控制外部设备的开关。我们将利用其他 Android API 来存储应用的设置，并在稍后使用它们来修改应用流程。


# 第六章：为智能家居构建 Chronotherm 电路

几十年来，控制家庭设备如灯光、恒温器和电器已经变得可能，甚至简单，通过自动和远程控制。一方面，这些自动化设备节省了人力和能源，但另一方面，即使是微小的调整对最终用户来说也不方便，因为他们需要对系统有很好的了解才能进行任何更改。

在过去几年中，由于缺乏标准或易于定制的解决方案，人们不愿采用**智能家居**技术。如今，情况正在发生变化，UDOO 等原型开发板在设计及构建**DIY**（**自己动手做**）自动化设备时发挥着重要作用。更妙的是，由于开源项目，这些平台易于扩展，并且可以被不同的设备控制，如个人电脑上的网络浏览器、手机和平板电脑。

在本章中，我们将涵盖以下主题：

+   探索智能家居的优势

+   构建一个 chronotherm 电路

+   发送数据与接收指令

+   编写 Chronotherm 安卓应用程序

# 智能家居

“智能家居”这个词相当通用，可能有多种不同的含义：控制环境灯光的定时器，响应来自外部的各种事件做出动作的智能系统，或者负责完成重复任务的编程设备。

这些都是智能家居的有效示例，因为它们共享同一个关键概念，使我们即使不在家也能管理家务和活动。智能家居设备通常在公共或私人网络上运行，以相互通信，以及与其他类型的设备如智能手机或平板电脑进行通信，接收指令或交换它们的状态信息。但当我们需要自动化简单的电器或电子元件，如灯泡时，该怎么办？解决这个问题的常见方法是通过开发一种**控制系统**设备，物理连接到我们想要管理的电器上；由于控制系统是一种智能家居设备，我们可以使用它来驱动它所连接的每个电器的行为。

如果我们在智能家居领域积累足够的经验，我们有可能开发并构建一个高端系统，用于我们自己的房子，这个系统足够灵活，可以轻松扩展，而不需要进一步的知识。

# 构建一个 chronotherm 电路

温控器主要由一个*控制单元*组成，负责检查环境温度是否低于预配置的设定点，如果是，则打开锅炉加热房间。这种行为很简单，但没有进一步的逻辑就不太有用。实际上，我们可以通过向温控器逻辑中添加*时间*参数来扩展此行为。这样，用户可以为每天每小时定义一个温度设定点，使温度检查更加智能。

### 注意

在这个原型中，控制单元是板载 Arduino，这是一个简化整体设计的实现细节。

这就是传统温控器的工作原理，为了实现它，我们应该：

+   构建带有温度传感器的电路

+   实现微控制器逻辑，以检查用户的设定点与当前温度

不幸的是，第二部分并不容易，因为用户的设定点应该存储在微控制器中，因此我们可以将这项任务委托给我们的安卓应用程序，通过在 microSD 卡中保存设置来实现。这种方法以下列方式解耦责任：

+   Arduino 草图：

    +   从温度传感器收集数据

    +   将检测到的温度发送到安卓

    +   期待一个安卓命令来启动或停止锅炉

+   安卓应用程序：

    +   管理用户交互

    +   实现用户设置，以存储每天每小时的温度设定点

    +   读取微控制器发送的温度

    +   实现逻辑以选择是否应该打开或关闭锅炉

    +   向微控制器发送命令以启动或停止锅炉

通过这个计划，我们可以依赖安卓用户界面组件轻松实现简洁且易用的界面，同时避免设置存储层的复杂性。

要开始构建原型，我们需要在我们的面包板上插入一个温度传感器，如*TMP36*，以获得以下电路：

![构建温控器电路](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_06_01.jpg)

以下是连接组件的逐步操作过程，如前图所示：

1.  将 TMP36 传感器放在面包板的右侧部分。

1.  将 UDOO 的+3.3V 引脚连接到电源总线的正极。确保不要连接+5V 电源引脚，因为未来连接时可能会损坏模拟输入引脚。

1.  将 UDOO 的地线连接到电源总线的负极。

1.  将 TMP36 传感器的左端连接到电源总线的正极。

    ### 提示

    使用封装传感器时，我们可以通过观察平整的部分来判断方向。使用这种方法来找到左端和右端。

1.  将 TMP36 传感器的右侧终端连接到电源总线的负极。

1.  将 TMP36 传感器的中间终端连接到模拟输入 A0。

这个封装的传感器非常容易使用，它不需要任何其他组件或电压分压器来为微控制器提供电压变化。现在我们应该继续从我们的电路管理锅炉点火。为了原型的需要，我们将用简单的 LED 替换锅炉执行器，就像我们在第二章，*了解你的工具*中所做的那样。这将使我们的电路更简单。

我们可以在面包板上添加一个 LED，以实现以下原理图：

![构建一个计时恒温电路](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_06_02.jpg)

以下是按照前述原理图连接组件的步骤：

1.  将 LED 放在面包板的左侧。

1.  将 LED 较长的终端（阳极）连接到 UDO 数字引脚 12。

1.  使用一个 220 欧姆的电阻，将 LED 较小的终端（阴极）连接到电源总线的负线上。

使用这个电路，我们拥有了从环境中收集数据和模拟锅炉点火所需的所有组件。现在我们需要打开 Arduino IDE 并开始一个新的草图。第一个目标是将检测到的温度检索并转换成方便的计量单位。为了实现这个目标，我们需要执行以下步骤：

1.  在草图的顶部定义这些类似对象宏和变量：

    ```kt
    #define TEMPERATURE_POLL_PERIOD 1000
    #define SENSOR A0
    #define BOILER 12
    int reading;
    ```

    我们定义了`SENSOR`对象来表示模拟引脚 A0，而`BOILER`对象与我们的数字引脚 12 相关联。我们还声明了一个`reading`变量，稍后用来存储当前检测到的温度。`TEMPERATURE_POLL_PERIOD`宏表示微控制器在两次读数之间等待的秒数，以及它通知 Android 应用程序检测到的温度之前等待的秒数。

1.  在`setup()`函数中，添加引脚模式声明并打开串行通信，如下所示：

    ```kt
    void setup() {
      pinMode(BOILER, OUTPUT);
      digitalWrite(BOILER, LOW);
      Serial.begin(115200);
    }
    ```

1.  在草图的底部，按照以下方式创建`convertToCelsius()`函数：

    ```kt
    float convertToCelsius(int value) {
      float voltage = (value / 1024.0) * 3.3;
      return (voltage - 0.5) * 100;
    }
    ```

    在这个函数中，我们期望一个传感器读数，并以*摄氏度*的形式返回它的表示。为此，我们使用了一些数学计算来确定实际检测到的电压是多少。因为 UDO 微控制器的模数转换器提供的值范围是[0-1023]，但我们想要计算从 0 到 3.3V 的范围，所以我们应该将值除以 1024.0，然后将结果乘以 3.3。

    我们在摄氏度转换中使用电压，因为如果我们阅读 TMP36 的数据表，我们会发现传感器每 10 毫伏的变化相当于 1 摄氏度的温度变化，这就是我们为什么将值乘以 100。我们还需要从电压中减去 0.5，因为此传感器可以处理 0 度以下的温度，而 0.5 是选择的偏移量。

    ### 提示

    这个函数可以将 TMP36 的读数轻松转换为摄氏度。如果你想使用其他计量单位，比如华氏度，或者你使用的是其他传感器或热敏电阻，那么你需要改变这个实现方式。

1.  在主`loop()`函数中，从传感器读取模拟信号并使用`loop()`函数打印转换后的结果：

    ```kt
    void loop() {
      reading = analogRead(SENSOR);
      Serial.print("Degrees C:");
      Serial.println(convertToCelsius(reading));
      delay(TEMPERATURE_POLL_PERIOD);
    }
    ```

如果我们上传草图并打开串行监视器，我们会注意到当前的室温。实际上，如果我们把手指放在传感器周围，我们会立即看到之前检测到的温度升高。以下屏幕截图是草图输出的一个示例：

![构建恒温器电路](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_06_03.jpg)

## 发送数据和接收命令

下一步是像往常一样启用 ADK 通信，并且我们需要在草图顶部添加*配件描述符*代码，如下所示：

```kt
#include <adk.h>
#define BUFFSIZE 128
char accessoryName[] = "Chronotherm";
char manufacturer[] = "Example, Inc.";
char model[] = "Chronotherm";
char versionNumber[] = "0.1.0";
char serialNumber[] = "1";
char url[] = "http://www.example.com";
uint8_t buffer[BUFFSIZE];
uint32_t readBytes = 0;
USBHost Usb;
ADK adk(&Usb, manufacturer, model, accessoryName, versionNumber, url, serialNumber);
```

现在我们需要将检测到的浮点温度发送回 Android 应用程序，就像我们在第五章，*管理与物理组件的交互*中所做的那样。为了将缓冲区加载一个浮点数并通过内部总线发送该值，我们需要添加一个`writeToAdk()`辅助函数，代码如下：

```kt
void writeToAdk(float temperature) {
  char tempBuffer[BUFFSIZE];
  sprintf(tempBuffer, "%f", temperature);
  memcpy(buffer, tempBuffer, BUFFSIZE);
  adk.write(strlen(tempBuffer), buffer);
}
```

前面的函数期望从传感器读数转换而来的浮点温度。我们使用`sprintf()`函数调用填充一个临时缓冲区，然后使用`memcpy()`函数用`tempBuffer`变量替换 ADK 缓冲区内容。加载完成后，我们将缓冲区内容发送到 Android 应用程序。

在主`loop()`函数中，我们还需要监听 Android 发送的任何命令，这些命令描述了需要打开或关闭锅炉的需求。因此，我们需要像在第二章，*了解你的工具*中所做的那样创建一个执行器函数。然后，我们需要从 ADK 读取命令并将结果传递给执行器。为此，我们需要执行以下步骤：

1.  添加`executor()`函数，该函数读取一个命令并打开或关闭外部设备：

    ```kt
    void executor(uint8_t command) {
      switch(command) {
        case 0:
          digitalWrite(BOILER, LOW);
          break;
        case 1:
          digitalWrite(BOILER, HIGH);
          break;
        default:
          // noop
          break;
      }
    }
    ```

1.  添加`executeFromAdk()`函数，该函数从 ADK 读取命令并将其传递给前面的`executor()`函数：

    ```kt
    void executeFromAdk() {
      adk.read(&readBytes, BUFFSIZE, buffer);
      if (readBytes > 0){
        executor(buffer[0]);
      }
    }
    ```

如果我们查看本章开始时定义的计划，我们拥有 Arduino 草图所需的所有组件，因此我们可以使用以下代码在主`loop()`函数中将所有内容组合在一起：

```kt
void loop() {
  Usb.Task();
  if (adk.isReady()) {
    reading = analogRead(SENSOR);
    writeToAdk(convertToCelsius(reading));
    executeFromAdk();
    delay(DELAY);
  }
}
```

当 ADK 准备就绪时，我们读取传感器值，并将其摄氏度转换写入 ADK 缓冲区。然后我们期望从 ADK 接收一个命令，如果命令可用，我们就执行该命令，打开或关闭锅炉。现在草图完成了，我们可以继续编写 Chronotherm Android 应用程序。

# 通过 Android 管理恒温器

当我们通过 UDOO 平台构建物理应用程序时，要牢记我们可以利用 Android 组件和服务来提升项目质量。此外，与硬件相比，Android 的用户界面元素更加用户友好且易于维护。因此，我们将创建一个软件组件来管理温度设定点，而不是使用电位计。

要开始应用程序原型设计，请打开 Android Studio 并启动一个名为**Chronotherm**的新应用程序，使用 Android API 19。在引导过程中，选择一个名为*Overview*的**空白活动**。

## 设置 ADK 工具包

在我们开始应用程序布局之前，需要配置 ADKToolkit 以实现内部通信。请遵循以下提示以完成正确的配置：

1.  在`app/build.gradle`文件中添加*ADKToolkit*库依赖。

1.  同步你的 Gradle 配置。

1.  在`res/xml/`目录下创建配件过滤器文件`usb_accessory_filter.xml`，包含以下代码：

    ```kt
    <resources>
      <usb-accessory
        version="0.1.0"
        model="Chronotherm"
        manufacturer="Example, Inc."/>
    </resources>
    ```

1.  在`AndroidManifest.xml`文件中添加*USB 配件支持*选项要求和*USB 配件意图过滤器*选项。

1.  在`Overview.java`类文件中，在类的顶部声明`AdkManager`对象。

1.  在`Overview`活动类的`onCreate()`方法中添加`AdkManager`对象初始化。

1.  重写`onResume()`活动回调，在活动打开时启动 ADK 连接。在这个项目中，我们在`onPause()`回调中不关闭 ADK 连接，因为我们将使用两个不同的活动，并且连接应该保持活动状态。

在 ADK 通信启动并运行后，我们可以继续编写 Chronotherm 用户界面。

## 设计 Android 用户界面

下一步是设计 Chronotherm 应用程序的用户界面，以处理设定点管理以及适当的反馈。我们将通过编写两个不同职责的 Android 活动来实现这些要求：

+   一个*Overview*活动，显示当前时间、检测到的温度和当前锅炉状态。它应该包括一个小组件，显示用户每天每个小时的设定点。这些设定点用于决定是否打开或关闭锅炉。

+   一个*Settings*活动，用于更改每天每个小时的当前设定点。这个活动应该使用与`Overview`活动相同的组件来表示温度设定点。

我们从`Overview`活动以及温度设定点小组件开始实现。

### 编写 Overview 活动

这个活动应提供有关 Chronotherm 应用程序当前状态的所有详细信息。所有必需的组件在以下模拟图中总结，该图定义了创建组件的顺序：

![编写 Overview 活动](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_06_04.jpg)

第一步是更新活动布局，根据前面草图的建议，我们应该执行以下步骤：

1.  在布局的顶部，我们可以包含一个显示当前系统时间的`TextClock`视图。

1.  顶栏应该提供锅炉状态的反馈。我们可以添加一个灰色的`TextView`，带有**Active**文字，当锅炉开启时它会变成绿色。

1.  `Overview`主体必须提供当前检测到的温度。因为这是 Chronotherm 应用程序提供的最重要的细节之一，我们将通过使其比其他组件更大来强调这个值。

1.  在室内温度附近，我们将通过一系列垂直条形图创建一个小部件，以显示用户每天每个小时的设定点，从而展示当前激活的日程。在`Overview`活动中，这个小部件将保持只读模式，仅用于快速查看激活的程序。

1.  在活动操作栏中，我们应该提供一个菜单项，用于打开`Settings`活动。这个活动将用于在 Chronotherm 应用程序中存储设定点。

我们从顶部栏和检测到的温度组件开始实现`Overview`，要实现前面的布局，需要以下步骤：

1.  在`res/values/dimens.xml`文件中，添加以下高亮资源：

    ```kt
    <resources>
      <dimen name="activity_horizontal_margin">16dp</dimen>
      <dimen name="activity_vertical_margin">16dp</dimen>
      <dimen name="text_title">40sp</dimen>
      <dimen name="temperature">100sp</dimen>
      <dimen name="temperature_round">300dp</dimen>
      <dimen name="circle_round">120dp</dimen>
    </resources>
    ```

1.  在`res/values/styles.xml`文件中，添加以下资源，并更改`AppTheme parent`属性如下：

    ```kt
    <resources>
      <color name="mine_shaft">#444444</color>
      <color name="pistachio">#99CC00</color>
      <color name="coral_red">#FF4444</color>
      <style name="AppTheme" parent="Theme.AppCompat"></style>
    </resources>
    ```

1.  为了强调当前检测到的温度，我们可以创建一个圆形形状来包围温度值。要实现这一点，请在`res/drawable/`目录下创建`circle.xml`文件，并添加以下代码：

    ```kt
    <shape

      android:shape="oval">

      <stroke
        android:width="2dp"
        android:color="@color/coral_red"/>

      <size
        android:width="@dimen/circle_round"
        android:height="@dimen/circle_round"/>
    </shape>
    ```

1.  现在我们可以继续并在`res/layout/`目录下的`activity_overview.xml`文件中替换布局，使用以下高亮代码：

    ```kt
    <LinearLayout 

      android:orientation="vertical"
      android:layout_width="match_parent"
      android:layout_height="match_parent"
      android:paddingLeft="@dimen/activity_horizontal_margin"
      android:paddingRight="@dimen/activity_horizontal_margin"
      android:paddingTop="@dimen/activity_vertical_margin"
      android:paddingBottom="@dimen/activity_vertical_margin"
      tools:context=".Overview">
    </LinearLayout>

    ```

1.  在前面的`LinearLayout`中放置以下代码，以创建包含当前系统时间和锅炉状态的活动顶栏：

    ```kt
    <LinearLayout
      android:layout_width="match_parent"
      android:layout_height="wrap_content">

      <TextClock
        android:textSize="@dimen/text_title"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content" />

      <TextView
        android:id="@+id/boiler_status"
        android:text="ACTIVE"
        android:gravity="end"
        android:textColor="@color/mine_shaft"
        android:textSize="@dimen/text_title"
        android:layout_width="match_parent"
        android:layout_height="wrap_content" />
    </LinearLayout>
    ```

1.  下一步是创建活动主体。它应该包含两个不同的项目：第一个是`LinearLayout`，我们将在活动的`onCreate()`回调中使用`LayoutInflater`类来填充设定点小部件；第二个是被我们之前创建的圆形形状包围的当前检测到的温度。在根`LinearLayout`中，嵌套以下元素：

    ```kt
    <LinearLayout
      android:orientation="horizontal"
      android:gravity="center"
      android:layout_width="match_parent"
      android:layout_height="match_parent">

      <LinearLayout
        android:id="@+id/view_container"
        android:gravity="center"
        android:orientation="horizontal"
        android:layout_width="0dp"
        android:layout_weight="1"
        android:layout_height="match_parent">
      </LinearLayout>

      <TextView
        android:id="@+id/temperature"
        android:text="20.5°"
        android:background="@drawable/circle"
        android:gravity="center"
        android:textColor="@color/coral_red"
        android:textSize="@dimen/temperature"
        android:layout_width="@dimen/temperature_round"
        android:layout_height="@dimen/temperature_round" />
    </LinearLayout>
    ```

1.  作为最后几步，在活动代码中存储所有视图引用。在`Overview`类的顶部，添加`temperature`和`boiler_status`视图的引用，使用以下高亮代码：

    ```kt
    private AdkManager mAdkManager;
    private TextView mTemperature;
    private TextView mStatus;

    ```

1.  在`Overview`的`onCreate()`回调中，使用以下代码获取引用：

    ```kt
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_overview);
    mTemperature = (TextView) findViewById(R.id.temperature);
    mStatus = (TextView) findViewById(R.id.boiler_status);

    ```

这些步骤提供了一个部分布局，我们将通过添加设定点小部件和设置菜单项来完成它。

### 创建自定义 UI 组件

为了保持用户界面的精简、可用和直观，我们可以使用一组垂直条，例如音频均衡器，以便用户可以立即了解他们想要获得的房间温度趋势。安卓自带一个名为`SeekBar`的内置组件，我们可以使用它来选择温度设定点。不幸的是，此组件绘制了一个水平条，并且没有提供其垂直对应物；因此，我们将扩展其默认行为。

### 注意

安卓 API 11 及更高版本为 XML 中的每个组件添加了`rotate`属性。即使我们使用 270 度的旋转来获得一个垂直组件，我们也可能会遇到正确放置一个条旁边另一个条的问题。在这种情况下，我们最初对定制此组件的努力将简化我们后续的工作。

安卓为构建自定义 UI 元素提供了复杂和组件化的模型，我们可以在[`developer.android.com/guide/topics/ui/custom-components.html`](http://developer.android.com/guide/topics/ui/custom-components.html)深入了解更多细节。

`SeekBar`组件的自定义可以按以下方式进行组织：

1.  作为第一步，我们应该创建一个实现垂直滑动行为的`TemperatureBar`类。大部分的更改与继承`SeekBar`类有关，同时将组件的宽度与高度进行切换。

1.  小部件需要一个 XML 布局，以便从我们的代码中程序化地添加。因此，我们将创建一个包含`TemperatureBar`视图、所选度数和与条相关的小时的布局。

1.  当垂直条组件发生任何变化时，应更新度数。在这一步中，我们将创建一个监听器，将条的变化传播到度数组件，为用户提供适当的反馈。

1.  我们定制的包含`TemperatureBar`类、度数和小时视图的组件，应该为一天中的每个小时程序化地创建。我们将创建一个工具类，负责将组件布局膨胀 24 次，并添加适当的监听器。

我们开始编写垂直的`SeekBar`类，可以通过以下步骤实现：

1.  在您的命名空间中创建一个名为`widget`的新包。

1.  在新创建的包中，添加一个扩展`SeekBar`类实现的`TemperatureBar`类，同时定义默认的类构造函数，如下所示：

    ```kt
    public class TemperatureBar extends SeekBar {
      public TemperatureBar(Context context) {
        super(context);
      }
      public TemperatureBar(Context context, AttributeSet attrs) {
        super(context, attrs);
      }
      public TemperatureBar(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
      }
    }
    ```

1.  继续实现`TemperatureBar`类，并在类的底部添加绘制和测量方法：

    ```kt
    @Override
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
      super.onSizeChanged(h, w, oldh, oldw);
    }

    @Override
    protected synchronized void onMeasure(int width, int height) {
      super.onMeasure(height, width);
      setMeasuredDimension(getMeasuredHeight(), getMeasuredWidth());
    }

    @Override
    protected void onDraw(Canvas c) {
      c.rotate(-90);
      c.translate(-getHeight(), 0);
      onSizeChanged(getWidth(), getHeight(), 0, 0);
      super.onDraw(c);
    }
    ```

    在第一个方法中，我们将小部件的宽度与高度进行切换，以便我们可以使用此参数来提供组件内容的准确测量。然后我们重写由安卓系统在组件绘制期间调用的`onDraw()`方法，通过对`SeekBar`画布应用平移并将其放置在垂直位置。作为最后一步，我们再次调用`onSizeChanged`回调以在画布平移后调整组件的大小。

1.  因为我们已经切换了条宽和高度，我们需要重写`onTouchEvent()`方法，以便在计算值时使用组件高度。在`TemperatureBar()`类的底部，添加以下回调：

    ```kt
    @Override
    public boolean onTouchEvent(MotionEvent event) {
      if (!isEnabled()) {
        return false;
      }
      switch (event.getAction()) {
        case MotionEvent.ACTION_DOWN:
        case MotionEvent.ACTION_MOVE:
        case MotionEvent.ACTION_UP:
          setProgress(getMax() - (int) (getMax() * event.getY() / getHeight()));
          onSizeChanged(getWidth(), getHeight(), 0, 0);
          break;
        case MotionEvent.ACTION_CANCEL:
          break;
      }
      return true;
    }
    ```

    使用前面的代码，我们每次在`ACTION_DOWN`、`ACTION_MOVE`或`ACTION_UP`方法事件发生时更新组件进度。由于本项目不需要其他行为，所以我们保留其余实现不变。

现在我们可以继续编写承载前一个组件以及度和小时的`TextView`的 XML 布局。通过以下步骤，我们可以实现一个从我们的工具类中填充的布局：

1.  在`res/values/`下的`dimens.xml`文件中添加`bar_height`声明，这样我们可以在需要时轻松地更改它：

    ```kt
    <dimen name="activity_horizontal_margin">16dp</dimen>
    <dimen name="activity_vertical_margin">16dp</dimen>
    <dimen name="bar_height">400dp</dimen>
    <dimen name="text_title">40sp</dimen>
    ```

1.  在`res/layout/`目录下创建`temperature_bar.xml`文件，其中包含小部件布局。在这个文件中，我们应该将此`LinearLayout`作为根元素添加：

    ```kt
    <LinearLayout 
      android:orientation="vertical"
      android:layout_width="0dp"
      android:layout_weight="1"
      android:layout_height="wrap_content">
    </LinearLayout>
    ```

1.  向前一个`LinearLayout`中包含以下组件：

    ```kt
    <TextView
      android:id="@+id/degrees"
      android:text="0"
      android:gravity="center"
      android:layout_width="match_parent"
      android:layout_height="match_parent" />

    <me.palazzetti.widget.TemperatureBar
      android:id="@+id/seekbar"
      android:max="40"
      android:layout_gravity="center"
      android:layout_width="wrap_content"
      android:layout_height="@dimen/bar_height" />

    <TextView
      android:id="@+id/time"
      android:text="00"
      android:gravity="center"
      android:layout_width="match_parent"
      android:layout_height="match_parent" />
    ```

    ### 提示

    始终将`me.palazzetti`命名空间替换为你的命名空间。

既然我们已经有了温度条组件和小部件布局，我们需要创建一个将`degrees`和`seekbar`视图绑定的绑定。通过以下步骤进行小部件实现：

1.  在`widget`包中创建`DegreeListener`类。

1.  前一个类应该实现`SeekBar`监听器，同时存储连接的`degrees`视图的引用。我们使用这个`TextView`引用来传播垂直条的价值：

    ```kt
    public class DegreeListener implements SeekBar.OnSeekBarChangeListener {
      private TextView mDegrees;
      public DegreeListener(TextView degrees) {
        mDegrees = degrees;
      }
    ```

1.  将进度值传播到`mDegrees`视图，覆盖`OnSeekBarChangeListener`接口所需的以下方法：

    ```kt
      @Override
      public void onProgressChanged(SeekBar seekBar, int progress, boolean b) {
        mDegrees.setText(String.valueOf(progress));
      }

      @Override
      public void onStartTrackingTouch(SeekBar seekBar) {}

      @Override
      public void onStopTrackingTouch(SeekBar seekBar) {}
    }
    ```

最后缺失的部分是提供一个工具类，用于初始化带有`DegreeListener`类的`TemperatureBar`类来填充小部件布局。该填充过程应针对一天的每个小时重复进行，并且需要引用小部件将被填充的布局。要完成实现，请按照以下步骤操作：

1.  在`widget`包中创建`TemperatureWidget`类。

1.  这个类应该公开一个静态的`addTo()`方法，该方法需要活动上下文、父元素以及是否应以只读模式创建垂直条。这样，我们可以将此小部件用于可视化和编辑。我们可以在以下代码片段中找到完整的实现：

    ```kt
    public class TemperatureWidget {
      private static final int BAR_NUMBER = 24;
      public static TemperatureBar[] addTo(Context ctx, ViewGroup parent, boolean enabled) {
        TemperatureBar[] bars = new TemperatureBar[BAR_NUMBER];
        for (int i = 0; i < BAR_NUMBER; i++) {
          View v = LayoutInflater.from(ctx).inflate(R.layout.temperature_bar, parent, false);
          TextView time = (TextView) v.findViewById(R.id.time);
          TextView degree = (TextView) v.findViewById(R.id.degrees);
          TemperatureBar bar = (TemperatureBar) v.findViewById(R.id.seekbar);
          time.setText(String.format("%02d", i));
          degree.setText(String.valueOf(0));
          bar.setOnSeekBarChangeListener(new DegreeListener(degree));
          bar.setProgress(0);
          bar.setEnabled(enabled);
          parent.addView(v, parent.getChildCount());
          bars[i] = bar;
        }
        return bars;
      }
    }
    ```

    在类的顶部，我们定义了生成的条形数的数量。在`addTo()`方法中，我们填充`temperature_bar`布局以创建条形对象的实例。然后，我们获取`time`、`degrees`和`seekbar`对象的所有引用，以便我们可以设置初始值并创建带有`degrees TextView`绑定的`DegreeListener`类。我们继续将小部件添加到`parent`节点，用当前创建的条形填充`bars`数组。最后一步，我们返回这个数组，以便调用活动可以使用它。

### 完成概览活动

设置点小部件现在已完成，我们可以继续在活动创建期间填充温度条。我们还将添加在活动菜单中启动`Settings`活动的操作。要完成`Overview`类，请按照以下步骤操作：

1.  在`Overview`的`onCreate()`回调中通过添加高亮代码来填充设置点小部件：

    ```kt
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_overview);
    mTemperature = (TextView) findViewById(R.id.temperature);
    mStatus = (TextView) findViewById(R.id.boiler_status);
    ViewGroup container = (ViewGroup) findViewById(R.id.view_container);
    mBars = TemperatureWidget.addTo(this, container, false);

    ```

1.  处理操作栏菜单以启动`Settings`活动，按照以下方式更改`onOptionsItemSelected()`方法：

    ```kt
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
      int id = item.getItemId();
      if (id == R.id.action_settings) {
        Intent intent = new Intent(this, Settings.class);
        startActivity(intent);
        return true;
      }
      return super.onOptionsItemSelected(item);
    }
    ```

    ### 注意

    `Settings`活动目前不可用，我们将在下一节中创建它。

我们已经完成了`Overview`类的布局，以下是获得的结果截图：

![完成概览活动](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_06_05.jpg)

### 编写设置活动

在实现我们的温控逻辑之前，下一步是创建一个`Settings`活动，以便在白天更改温度设置点。要启动新活动，请从窗口菜单中选择**文件**，然后选择**新建**以打开上下文菜单。在那里，选择**活动**，然后选择**空白活动**。这将打开一个新窗口，我们可以在**活动名称**中填写`Settings`，然后点击**完成**。

### 注意

即使我们可以使用带有同步首选项的内置设置模板，我们还是使用空白活动以尽可能简化这部分内容。

我们从以下草图开始设计活动布局，展示所有必需的组件：

![编写设置活动](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_06_06.jpg)

首先需要更新活动布局，根据之前草图的建议，我们应该：

1.  添加一个**保存**按钮，该按钮将调用活动方法，保存从温度小部件中选择的设置点。

1.  在选择设置点期间，填充使用的温度小部件。

为了实现前面的布局，更新`res/layout/`下的`activity_settings.xml`文件，进行以下更改：

1.  使用以下`LinearLayout`替换根布局元素：

    ```kt
    <LinearLayout 

      android:orientation="vertical"
      android:layout_width="match_parent"
      android:layout_height="match_parent"
      android:paddingLeft="@dimen/activity_horizontal_margin"
      android:paddingRight="@dimen/activity_horizontal_margin"
      android:paddingTop="@dimen/activity_vertical_margin"
      android:paddingBottom="@dimen/activity_vertical_margin"
      tools:context="me.palazzetti.chronotherm.Settings">
    </LinearLayout>

    ```

1.  在前面的布局中，添加小部件占位符和**保存**按钮：

    ```kt
    <LinearLayout
      android:id="@+id/edit_container"
      android:orientation="horizontal"
      android:layout_width="match_parent"
      android:layout_height="wrap_content">
    </LinearLayout>

    <Button
      android:text="Save settings"
      android:layout_marginTop="50dp"
      android:layout_width="match_parent"
      android:layout_height="wrap_content" />
    ```

我们可以通过在`Settings`类中进行以下步骤，添加小部件初始化来完成活动：

1.  在`Settings`类顶部添加高亮变量：

    ```kt
    public class Settings extends ActionBarActivity {
      private TemperatureBar[] mBars;
      // ... 
    ```

1.  在`Settings`类的`onCreate()`方法中，添加高亮代码以填充设置点小部件：

    ```kt
    @Override
    protected void onCreate(Bundle savedInstanceState) {
      super.onCreate(savedInstanceState);
      setContentView(R.layout.activity_settings);
      ViewGroup container = (ViewGroup)   findViewById(R.id.edit_container);
      mBars = TemperatureWidget.addTo(this, container, true);
    }
    ```

如果我们再次上传 Android 应用程序，可以使用菜单选项打开`Settings`活动，如下截图所示：

![编写 Settings 活动](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_06_07.jpg)

Chronotherm 应用程序的界面已完成，我们可以继续处理用户设置存储层的管理。

## 管理用户的设定点

Chronotherm 应用程序的活动提供了必要的用户界面组件，以显示和更改用户的设定点。为了让它们工作，我们应该实现保存持久应用程序数据的逻辑。根据我们的需求，我们可以使用`SharedPreferences`类以键值对的形式存储基本数据，为整个应用程序提供设定点值。在这个项目中，我们将使用设定点小时作为键，选择的温度作为值。

### 注意事项

`SharedPreferences`类是 Android 框架提供的一种存储选项。如果在其他项目中我们需要不同的存储方式，可以查看 Android 官方文档：[developer.android.com/guide/topics/data/data-storage.html](http://developer.android.com/guide/topics/data/data-storage.html)。

### 从 Overview 活动中读取设定点

我们首先在`Overview`活动中实现一个方法，该方法读取存储的设定点并更新温度条数值。在活动创建期间，我们可以通过以下步骤读取用户的偏好设置：

1.  对于每个进度条，我们使用存储的值来设置进度。当没有找到设置时，我们使用`0`作为默认值。这个实现需要以下代码，我们应该将其添加到`Overview`类中：

    ```kt
    private void readPreferences() {
      SharedPreferences sharedPref = getSharedPreferences("__CHRONOTHERM__", Context.MODE_PRIVATE);
      for (int i = 0; i < mBars.length; i++) {
        int value = sharedPref.getInt(String.valueOf(i), 0);
        mBars[i].setProgress(value);
      }
    }
    ```

    我们打开应用程序的偏好设置，并使用一天中的小时作为键来更新每个条形图。相关的小时由`i`循环计数器间接表示。

1.  从`onResume()`活动回调中调用前面的方法，并添加高亮显示的代码：

    ```kt
    protected void onResume() {
      super.onResume();
      readPreferences();
      mAdkManager.open();
    }
    ```

通过这些步骤，我们在`Overview`活动中完成了设定点的管理，并将继续处理`Settings`活动。

### 从 Settings 活动中写入设定点

在`Settings`活动中，当用户点击**保存设置**按钮时，我们应该实现存储用户设定点的逻辑。此外，当活动创建时，我们必须加载先前存储的设定点，以便在用户开始更改偏好设置之前，向他们展示当前的时间表。为实现这些功能，我们可以按照以下步骤进行：

1.  与在`Overview`活动中所做的一样，我们需要加载设定点值并更新温度条。因为我们已经实现了这个功能，所以可以直接从`Overview`类将`readPreferences()`方法复制粘贴到`Settings`类中。

1.  在`Settings`类的底部添加以下代码以存储选定的设定点：

    ```kt
    public void savePreferences(View v) {
      SharedPreferences sharedPref = getSharedPreferences("chronotherm", Context.MODE_PRIVATE);
      SharedPreferences.Editor editor = sharedPref.edit();
      for (int i = 0; i < mBars.length; i ++) {
        editor.putInt(String.valueOf(i), mBars[i].getProgress());
      }
      editor.apply();
      this.finish();
    }
    ```

    在使用后台提交检索并存储所有设定点之后，我们关闭当前活动。

1.  在`res/layout/`下的`activity_settings.xml`布局文件中，更新保存按钮，使其在点击时调用前面的方法，如以下高亮代码所示：

    ```kt
    <Button
      android:onClick="savePreferences"
      android:text="Save settings"
      android:layout_marginTop="50dp"
      android:layout_width="match_parent"
      android:layout_height="wrap_content" />
    ```

这是实现 Chronotherm 应用程序接口和设置管理的最后一步。现在我们可以继续实现读取检测到的温度以及开启或关闭锅炉所需的逻辑。

## 与 Arduino 交互

我们的应用程序已准备好接收温度数据，检查是否应激活锅炉。整体设计是使用`ExecutorService`类，该类运行周期性的计划任务线程，并且应该：

1.  从 ADK 读取检测到的温度。

1.  更新锅炉状态，检查温度是否低于当前选择的设定点。

1.  将温度发送到主线程，以便它可以更新`temperature` `TextView`。

1.  向 Arduino 发送命令以开启或关闭锅炉。此任务应仅在当前锅炉状态自上一次任务执行以来发生变化时执行。在这种情况下，它还应将锅炉状态发送到主线程，以便它可以更新相关的`TextView`。

在我们开始线程实现之前，我们应该提供一个 Java 接口，它公开了更新活动用户界面所需的必要方法。我们可以通过以下步骤完成此操作：

1.  创建一个名为`OnDataChangeListener`的新 Java 接口，并添加以下代码片段：

    ```kt
    public interface OnDataChangeListener {
      void onTemperatureChanged(float temperature);
      void onBoilerChanged(boolean status);
    }
    ```

1.  使用高亮代码将前面的接口添加到`Overview`类：

    ```kt
    public class Overview extends ActionBarActivity implements OnDataChangeListener {
    ```

1.  通过编写更新当前温度和锅炉状态`TextViews`的代码来实现接口：

    ```kt
    @Override
    public void onTemperatureChanged(float temperature) {
      mTemperature.setText(String.format("%.1f°", temperature));
    }

    @Override
    public void onBoilerChanged(boolean status) {
      if (status) {
        mStatus.setTextColor(getResources().getColor(R.color.pistachio));
      }
      else {
        mStatus.setTextColor(getResources().getColor(R.color.mine_shaft));
      }
    }
    ```

现在我们可以继续实现先前解释的整体设计的计划任务线程：

1.  在您的命名空间中创建一个名为`adk`的新包。

1.  在`adk`包中，添加一个名为`DataReader`的新类。

1.  在类的顶部，添加以下声明：

    ```kt
    private final static int TEMPERATURE_POLLING = 1000;
    private final static int TEMPERATURE_UPDATED = 0;
    private final static int BOILER_UPDATED = 1;
    private AdkManager mAdkManager;
    private Context mContext;
    private OnDataChangeListener mCaller;
    private ScheduledExecutorService mSchedulerSensor;
    private Handler mMainLoop;
    boolean mBoilerStatus = false;
    ```

    我们定义了计划任务的轮询时间以及主线程处理器中使用的消息类型，以识别温度或锅炉更新。我们保存了`AdkManager`实例、活动上下文以及实现前一个接口的调用活动引用。然后，我们定义了将用于创建短生命周期的线程以读取传感器数据的`ExecutorService`实现。

1.  实现设置消息处理器的`DataReader`构造函数，当主线程从传感器线程接收到消息时：

    ```kt
    public DataReader(AdkManager adkManager, Context ctx, OnDataChangeListener caller) {
      this.mAdkManager = adkManager;
      this.mContext = ctx;
      this.mCaller = caller;
      mMainLoop = new Handler(Looper.getMainLooper()) {
        @Override
        public void handleMessage(Message message) {
          switch (message.what) {
            case TEMPERATURE_UPDATED:
              mCaller.onTemperatureChanged((float) message.obj);
              break;
            case BOILER_UPDATED:
              mCaller.onBoilerChanged((boolean) message.obj);
              break;
          }
        }
      };
    }
    ```

    我们保存所有必要的引用，然后定义主线程处理器。在处理器内部，我们使用`OnDataChangeListener`回调根据消息类型在视图中更新温度或锅炉状态。

1.  在`DataReader`构造函数的底部，添加以下实现了先前定义的整体设计的`Runnable`方法：

    ```kt
    private class SensorThread implements Runnable {
      @Override
      public void run() {
        Message message;
        // Reads from ADK and check boiler status
        AdkMessage response = mAdkManager.read();
        float temperature = response.getFloat();
        boolean status = isBelowSetpoint(temperature);
        // Updates temperature back to the main thread
        message = mMainLoop.obtainMessage(TEMPERATURE_UPDATED, temperature);
        message.sendToTarget();
        // Turns on/off the boiler and updates the status
        if (mBoilerStatus != status) {
          int adkCommand = status ? 1 : 0;
          mAdkManager.write(adkCommand);
          message = mMainLoop.obtainMessage(BOILER_UPDATED, status);
          message.sendToTarget();
          mBoilerStatus = status;
        }
      }
      private boolean isBelowSetpoint(float temperature) {
        SharedPreferences sharedPref = mContext.getSharedPreferences("__CHRONOTHERM__", Context.MODE_PRIVATE);
        int currentHour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY);
        return temperature < sharedPref.getInt(String.valueOf(currentHour), 0);
      }
    }
    ```

    在这个实现中，我们创建了一个`isBelowSetpoint()`方法，用于检查当前小时的温度是否低于所选的设定点。我们从应用程序的共享偏好设置中获取这个值。

1.  向`DataReader`类添加一个方法，以定期创建短生命周期的线程来启动调度程序，如下所示：

    ```kt
    public void start() {
      // Start thread that listens to ADK
      SensorThread sensor = new SensorThread();
      mSchedulerSensor = Executors.newSingleThreadScheduledExecutor();
      mSchedulerSensor.scheduleAtFixedRate(sensor, 0, TEMPERATURE_POLLING, TimeUnit.MILLISECONDS);
    }
    ```

1.  在类的底部添加`stop()`方法，通过执行器的`shutdown()`方法停止调度程序创建新线程：

    ```kt
    public void stop() {
      mSchedulerSensor.shutdown();
    }
    ```

1.  现在，我们应该回到`Overview`类中，在活动生命周期内开始和停止调度程序。在`Overview`类的顶部添加`DataReader`声明：

    ```kt
    private AdkManager mAdkManager;
    private DataReader mReader;

    ```

1.  在`onCreate()`回调中初始化`DataReader`实例，通过以下突出显示的代码：

    ```kt
      mAdkManager = new AdkManager(this);
      mReader = new DataReader(mAdkManager, this, this);
    }
    ```

1.  在`onResume()`和`onPause()`活动的回调中开始和停止读取调度程序，如突出显示的代码所示：

    ```kt
    @Override
    protected void onPause() {
      super.onPause();
      mReader.stop();
    }

    @Override
    protected void onResume() {
      super.onResume();
      readPreferences();
      mAdkManager.open();
      mReader.start();
    }
    ```

UDOO 和 Android 之间的通信已经运行起来，我们恒温器的逻辑已经准备好激活和关闭锅炉。现在，我们可以再次上传 Android 应用程序，添加一些温度设置，并开始玩原型。我们已经完成了原型，最后缺少的任务是在`app/build.gradle`文件中将应用程序版本更新为`0.1.0`版本，如下面的代码所示：

```kt
defaultConfig {
  applicationId "me.palazzetti.chronotherm"
  minSdkVersion 19
  targetSdkVersion 21
  versionCode 1
  versionName "0.1.0"
}
```

# 改进原型

在本章中，我们做出了不同的设计决策，使恒温器的实现更加容易。尽管这个应用程序对于家庭自动化来说是一个很好的概念验证，但我们必须牢记，还需要做很多事情来提高原型的质量和可靠性。这个应用程序是一个经典场景，分别用 Android 应用程序和 Arduino 微控制器实现了**人机界面（HMI）**和**控制系统**。在这种场景中，自动化设计的一个基本原则是，即使在没有 HMI 部分的情况下，控制单元也应该能够做出*合理且安全的决策*。

在我们的案例中，我们解耦了责任，将打开或关闭锅炉的决定委托给 Android 应用程序。虽然这不是一个任务关键的系统，但这样的设计可能会导致如果 Android 应用程序崩溃，锅炉可能会永远保持开启状态。更好的解耦方式是只使用 HMI 显示反馈和存储用户的设定点，而改变锅炉状态的决定仍然留在控制单元中。这意味着，我们不应该向 Arduino 发送开或关的命令，而应该发送当前的设定点，该设定点将存储在微控制器的内存中。这样，控制单元可以根据最后收到的设定点做出安全的选择。

另一个我们可以作为练习考虑的改进是实施**滞后逻辑**。我们的恒温器设计为在检测到的温度超过或低于选定设定点时分别开启或关闭锅炉。这种行为应该得到改进，因为在这种设计中，当温度稳定在设定点周围时，恒温器将开始频繁地开启和关闭锅炉。我们可以在[控制系统的滞后逻辑应用](http://en.wikipedia.org/wiki/Hysteresis#Control_systems)中找到有关详细信息和建议。

# 总结

在本章中，我们探讨了智能家居领域以及如何使用 UDOO 解决一些日常任务。你了解了使用智能对象的优势，这些对象能够在你不在家时解决地点和时间问题。然后，我们规划了一个恒温器原型，通过传感器控制我们的客厅温度。为了使设备完全自动化，我们设计了一个用例，用户可以决定每天每个小时的温度设定点。

起初，我们使用温度传感器和 LED 构建了应用电路，模拟了锅炉。我们开始编写 Android 用户界面程序，自定义常规 UI 组件以更好地满足我们的需求。我们开始编写概述活动，显示当前时间、锅炉状态、当前室温以及全天选择的设定点的小部件。接着，我们继续编写设置活动，用于存储恒温器温度计划。作为最后一步，我们编写了一个计划任务线程，读取环境温度并根据检测到的温度与当前设定点匹配来开启或关闭锅炉。

在下一章中，我们将利用一系列强大的 Android API 扩展此原型，增加新功能以增强人与设备的交互。


# 第七章：使用 Android API 进行人机交互

20 世纪 80 年代个人电脑的出现开启了一个新的挑战：让电脑和计算对业余爱好者、学生以及更广泛的技术爱好者有用和可用。这些人需要一个简单的方法来控制他们的机器，因此人机交互迅速成为一个开放的研究领域，旨在提高可用性，并导致了图形用户界面和新型输入设备的发展。在过去的十年中，诸如语音识别、语音合成、动作追踪等其他的交互模式在商业应用中被使用，这一巨大改进间接导致了电话、平板和眼镜等物体向新型智能设备的演变。

本章的目标是利用这些新的交互模式，使用 Android API 的一个子集来增强 Chronotherm 原型，增加一组新功能，使其变得更加智能。

在本章中，我们将涵盖以下主题：

+   利用 Android API 扩展原型

+   使用语音识别来控制我们的原型

+   通过语音合成向用户提供反馈

# 利用 Android API 扩展原型

Chronotherm 应用程序旨在当检测到的温度超过用户的温度设定点时启动锅炉。在之前的原型中，我们创建了一个设置页面，用户可以设置他们每天每个小时的偏好。我们可以扩展原型的行为，让用户能够存储不止一个设定点配置。这样，我们可以提供预设管理，用户可以根据不同的因素，如星期几或当前季节来激活。

在添加此功能时，我们必须牢记这并不是一个桌面应用程序，因此我们应避免创建一组新的令人眼花缭乱的界面。Chronotherm 应用程序可以部署在用户的家中，由于这些地方通常很安静，我们可以考虑使用**语音识别**来获取用户的输入。这种方法将消除创建或编辑存储预设的其他活动的需要。同时，我们必须考虑到在语音识别过程结束时我们需要提供反馈，以便用户知道他们的命令是否被接受。即使我们可以使用小弹窗或通知来解决此问题，但使用**语音合成**来向用户提供反馈可以带来更好的用户体验。

### 注意

语音识别和合成是可以用来为我们的应用程序提供新型交互的功能。然而，我们必须牢记，这些组件可能会为视障、身体障碍或听障人士带来严重的可访问性问题。每次我们想要创建一个好的项目时，都必须努力工作，以制作出既美观又可供每个人使用的应用程序。安卓通过**可访问性框架**为我们提供了很大帮助，因此，在未来的项目中，请记得遵循[`developer.android.com/guide/topics/ui/accessibility/index.html`](https://developer.android.com/guide/topics/ui/accessibility/index.html)上提供的所有最佳实践。

安卓 SDK 提供了一系列 API，我们可以用它们与安装的文字转语音服务和语音输入法进行交互，但是 UDOOU 盘自带的**原生安卓**并没有直接提供这些功能。为了让我们的代码工作，我们需要安装一个用于语音识别的应用程序，以及另一个实现文字转语音功能的应用。

例如，市场上几乎任何安卓设备都预装了作为**谷歌移动服务**套件一部分的这类应用程序。有关此主题的更多详细信息，请点击链接[`www.udoo.org/guide-how-to-install-gapps-on-udoo-running-android/`](http://www.udoo.org/guide-how-to-install-gapps-on-udoo-running-android/)。

# 改进用户设置

在我们继续实现语音识别服务之前，需要改变物理应用程序中设置存储的方式。目前，我们正在使用 Chronotherm 应用程序的共享偏好设置，我们在其中存储每个`SeekBar`类选择的设定点。根据新要求，这不再适合我们的应用程序，因为我们需要为每个预设持久化不同的设定点。此外，我们需要持久化当前激活的预设，所有这些变化都迫使我们设计一个新的用户界面以及一个新的设置系统。

我们可以通过以下截图来看看需要做出哪些改变：

![改进用户设置](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_07_01.jpg)

第一步是更新我们的用户界面。根据上述草图的建议，我们应该：

1.  在布局顶部添加一个新的`TextView`，显示当前预设的名称。在加载活动时以及用户激活新预设时，应更改名称。

为了实现上述布局，更新`res/layout/`目录下的`activity_overview.xml`文件，在包含`TextClock`和`boiler_status`视图的头部`LinearLayout`中进行以下更改：

1.  更改`TextClock`视图，用高亮代码替换`layout_width`属性，并添加`layout_weight`属性：

    ```kt
    android:layout_width="0dp"
    android:layout_weight="1"

    ```

1.  按照上一步的操作，更改`boiler_status` `TextView`的布局：

    ```kt
    android:layout_width="0dp"
    android:layout_weight="1"

    ```

1.  在前一个组件之间添加以下`TextView`以显示激活的预设：

    ```kt
    <TextView
      android:id="@+id/current_preset"
      android:text="NO PRESET ACTIVATED"
      android:gravity="center"
      android:textColor="@color/coral_red"
      android:textSize="@dimen/text_title"
      android:layout_width="0dp"
      android:layout_weight="2"
      android:layout_height="match_parent" />
    ```

1.  在 `Overview` 类的顶部，使用高亮代码添加 `current_preset` 视图的引用：

    ```kt
    private TextView mCurrentPreset;
    private TextView mTemperature;
    private TextView mStatus;
    ```

1.  在 `Overview` 的 `onCreate` 回调中，使用以下代码获取视图引用：

    ```kt
    setContentView(R.layout.activity_overview);
    mCurrentPreset = (TextView) findViewById(R.id.current_preset);

    ```

下面的截图是通过前面的布局获得的：

![改善用户设置](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_07_02.jpg)

## 存储预设配置

如先前讨论的，我们应该改变 Chronotherm 应用程序中用户设置点的存储和检索方式。想法是将对应用程序共享首选项的访问隔离在一个新的 `Preset` 类中，该类公开以下方法：

+   一个 `set()` 方法，用于保存与预设名称对应的设置点配置。设置点值数组被序列化为逗号分隔的字符串，并使用预设名称作为键进行保存。

+   一个 `get()` 方法，用于返回给定预设名称的存储设置点。设置点字符串被反序列化并作为值数组返回。

+   一个 `getCurrent()` 方法，用于返回最新激活预设的名称。

+   一个 `setCurrent()` 方法，用于将给定的预设名称提升为最新激活的预设。

要创建 `Preset` 类，请按照以下步骤操作：

1.  在 `chronotherm` 包中创建 `Preset` 类。

1.  在 `Preset` 类的顶部添加以下声明：

    ```kt
    private static final String SHARED_PREF = "__CHRONOTHERM__";
    private static final String CURRENT_PRESET = "__CURRENT__";
    private static final String NO_PRESET = "NO PRESET ACTIVATED";
    ```

    我们将前一章中使用的偏好设置名称放在一个名为 `SHARED_PREF` 的变量中。`CURRENT_PRESET` 键用于获取或设置当前使用的预设。`NO_PRESET` 赋值定义了在没有找到预设时返回的默认值。这处理了首次运行应用程序的情况，在没有找到预设时显示 **NO PRESET ACTIVATED** 屏幕。

1.  在 `Preset` 类的底部添加 `set()` 方法：

    ```kt
    public static void set(Context ctx, String name, ArrayList<Integer> values) {
      SharedPreferences sharedPref = ctx.getSharedPreferences(SHARED_PREF, Context.MODE_PRIVATE);
      SharedPreferences.Editor editor = sharedPref.edit();
      String serializedValues = TextUtils.join(",", values);
      editor.putString(name, serializedValues);
      editor.apply();
    }
    ```

    前面的方法期望 `values` 数组，该数组表示给定预设 `name` 变量的用户设置点。我们使用 `TextUtils` 类将值数组序列化为逗号分隔的字符串，同时使用预设 `name` 变量作为键。

1.  在 `Preset` 类的底部添加 `get()` 方法：

    ```kt
    public static ArrayList<Integer> get(Context ctx, String name) {
      ArrayList<Integer> values = new ArrayList<Integer>();
      SharedPreferences sharedPref = ctx.getSharedPreferences(SHARED_PREF, Context.MODE_PRIVATE);   String serializedValues = sharedPref.getString(name, null);
      if (serializedValues != null) {
        for (String progress : serializedValues.split(",")) {
          values.add(Integer.valueOf(progress));
        }
      }
      return values;
    }
    ```

    我们用预设的 `name` 变量获取到的设置点填充 `values` 数组。我们知道这些值是以逗号分隔的序列化字符串，因此我们将其拆分并解析，将每个值添加到前面的数组中。如果我们没有找到与给定预设 `name` 变量相匹配的内容，我们将返回一个空数组。

1.  在类的底部添加 `getCurrent()` 方法，以返回当前激活的预设：

    ```kt
    public static String getCurrent(Context ctx) {
      String currentPreset;
      SharedPreferences sharedPref = ctx.getSharedPreferences(SHARED_PREF, Context.MODE_PRIVATE);
      currentPreset = sharedPref.getString(CURRENT_PRESET, NO_PRESET);
      return currentPreset;
    }
    ```

1.  在类的底部添加 `setCurrent()` 方法，以存储当前激活的预设：

    ```kt
    public static void setCurrent(Context ctx, String name) {
      SharedPreferences sharedPref = ctx.getSharedPreferences(SHARED_PREF, Context.MODE_PRIVATE);
      SharedPreferences.Editor editor = sharedPref.edit();
      editor.putString(CURRENT_PRESET, name);
      editor.apply();
    }
    ```

既然我们已经有了用户预设的正式表示，我们应该调整这两个活动以反映最新的变化。

## 在活动间使用预设

我们从`概览`活动开始，该活动应在活动恢复阶段加载当前预设。如果激活了预设，我们应该将`current_preset` `TextView`更改为预设名称。为实现此步骤，我们应该用以下代码替换`readPreferences`方法：

```kt
private void readPreferences() {
  String activatedPreset = Preset.getCurrent(this);
  mCurrentValues = Preset.get(this, activatedPreset);
  for (int i = 0; i < mCurrentValues.size(); i++) {
    mBars[i].setProgress(mCurrentValues.get(i));
  }
  mCurrentPreset.setText(activatedPreset.toUpperCase());
}
```

下一步是使`设置`活动适应以下步骤总结的新行为：

1.  当用户打开`设置`活动时，语音识别系统应该请求预设名称。

1.  如果找到给定的预设，我们应该加载预设的设定点，并更新所有温度条。当用户保存新偏好时，旧的设定点将被更新。

1.  如果未找到给定的预设，则无需更新温度条。当用户保存新偏好时，将使用给定的设定点存储新的预设条目。

我们仍然没有实现第一步所需的所有组件，因为我们缺少语音识别实现。与此同时，我们可以通过以下步骤更新此活动中的预设存储和检索方式：

1.  在类的顶部，添加突出显示的变量，该变量将存储识别的预设名称：

    ```kt
    private TemperatureBar[] mBars;
    private String mEditingPreset;

    ```

1.  在`设置`活动的`onCreate()`回调中，移除`readPreferences()`方法的调用。

1.  更新`readPreferences()`成员函数，使其加载给定预设名称（如果可用）的值，并返回表示是否找到此预设的值。我们可以通过以下代码实现此行为：

    ```kt
    private boolean readPreferences(String presetName) {
      boolean found;
      ArrayList<Integer> values;
      values = Preset.get(this, presetName);
      found = values.size() > 0;
      for (int i = 0; i < values.size(); i ++) {
        mBars[i].setProgress(values.get(i));
      }
      return found;
    }
    ```

1.  更新`savePreferences()`方法，使其使用`Preset`类来存储或更新给定的设定点：

    ```kt
    public void savePreferences(View v) {
      ArrayList<Integer> values = new ArrayList<Integer>();
      for (int i = 0; i < mBars.length; i++) {
        values.add(mBars[i].getProgress());
      }
      Preset.set(this, mEditingPreset, values);
      this.finish();
    }
    ```

通过这些步骤，我们在两个活动中都改变了预设管理。我们仍然需要完成`设置`活动，因为我们缺少识别阶段。我们将在实现语音识别后，稍后完成这些步骤。

在将 Chronotherm 应用程序适应新的预设管理的最后一步，是更改`SensorThread`参数中的温度检查。实际上，`isBelowSetpoint`方法应该检索与最后温度读数匹配的激活预设的此设定点的值。如果选择了任何预设，它应该默认关闭锅炉。我们可以通过用突出显示的代码更改`isBelowSetpoint`方法来实现此行为：

```kt
private boolean isBelowSetpoint(float temperature) {
  int currentHour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY);
  String currentPreset = Preset.getCurrent(mContext);
  ArrayList<Integer> currentValues = Preset.get(mContext,   currentPreset);
  if (currentValues.size() > 0) {
    return temperature < currentValues.get(currentHour);
  }
  else {
    return false;
  }
}
```

这结束了`预设`配置过程，现在我们可以继续实现语音识别。

# 实现语音识别

既然我们的原型可以处理不同的预设，我们应该提供一种快速的方法，通过语音识别来更改、创建或编辑用户预设。管理语音识别的最简单方法之一是使用 Android 的`Intent`消息对象，将此操作委托给另一个应用程序组件。正如我们在本章开头所讨论的，如果我们安装并配置了一个符合要求的语音输入应用程序，Android 可以使用它进行语音识别。

主要目标是提供一个抽象类，供我们的活动扩展以管理识别回调，同时避免代码重复。整体设计如下：

+   我们应该为需要语音识别的活动提供一个通用接口。

+   我们应该提供一个`startRecognition()`方法，通过`Intent`对象启动识别活动。

+   我们应该实现`onActivityResult()`回调，当启动的活动完成语音识别时将调用此回调。在这个回调中，我们使用在语音识别过程中产生的所有结果中最好的一个。

    ### 注意

    作业委托是 Android 操作系统最有用的功能之一。如果你需要更多信息了解它的工作原理，请查看 Android 官方文档 [`developer.android.com/guide/components/intents-filters.html`](http://developer.android.com/guide/components/intents-filters.html)。

以下步骤可以实现重用语音识别能力的先前抽象：

1.  在`chronotherm`包中添加`IRecognitionListener`接口，定义`onRecognitionDone()`回调，用于将结果发送回调用活动。我们可以通过以下代码实现这一点：

    ```kt
    public interface IRecognitionListener {
      void onRecognitionDone(int requestCode, String bestMatch);
    }
    ```

1.  创建一个名为`voice`的新包，并添加一个名为`RecognizerActivity`的新抽象类。该类应定义如下：

    ```kt
    public abstract class RecognizerActivity extends ActionBarActivity implements IRecognitionListener {
    }
    ```

1.  添加一个公共方法来初始化识别阶段，并将获取结果的责任委托给以下代码：

    ```kt
    public void startRecognition(String what, int requestCode) {
      Intent intent = new Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH);
      intent.putExtra(RecognizerIntent.EXTRA_LANGUAGE, "en-US");
      intent.putExtra(RecognizerIntent.EXTRA_PROMPT, what);
      startActivityForResult(intent, requestCode);
    }
    ```

    `requestCode`参数是识别`Intent`的标识符，由调用活动使用以正确识别结果以及如何处理它。`what`参数用于提供屏幕消息，如果外部应用程序支持的话。

1.  添加`onActivityResult()`回调以提取最佳结果，并通过通用接口将其传递给调用活动：

    ```kt
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
      if (resultCode == RESULT_OK) {
        ArrayList<String> matches = data.getStringArrayListExtra(RecognizerIntent.EXTRA_RESULTS);
        this.onRecognitionDone(requestCode, matches.get(0));
      }
    }
    ```

## 使用语音识别添加或编辑预设

通过`RecognizerActivity`类，我们将繁重的工作委托给 Android 框架。根据活动的性质，我们应该以不同的方式处理结果。我们在活动创建阶段使用`Settings`活动开始使用语音输入，询问我们想要创建或编辑的预设名称。如果预设存在，我们应在保存过程中加载存储的设定点并更新它们。否则，我们应在偏好设置中创建新的记录。为了实现这种行为，请执行以下步骤：

1.  根据以下代码片段，从`Settings`类扩展`RecognizerActivity`：

    ```kt
    public class Settings extends RecognizerActivity {
      //...
    }
    ```

1.  声明我们将用于识别和处理识别结果的意图请求代码。在类的顶部，添加以下高亮代码：

    ```kt
    public class Settings extends RecognizerActivity {
      private static final int VOICE_SETTINGS = 1001;
      private TemperatureBar[] mBars;
      // ...
    }
    ```

1.  在`onCreate()`回调的底部，添加以下代码以尽快开始语音识别：

    ```kt
    mBars = TemperatureWidget.addTo(this, container, true);
    startRecognition("Choose the preset you want to edit", VOICE_SETTINGS);

    ```

1.  实现`onRecognitionDone()`回调，这是之前定义的`IRecognitionListener`接口所要求的，以处理识别意图返回的结果。在类的底部，添加以下代码：

    ```kt
    @Override
    public void onRecognitionDone(int requestCode, String bestMatch) {
      if (requestCode == VOICE_SETTINGS) {
        boolean result = readPreferences(bestMatch);
        mEditingPreset = bestMatch;
      }
    }
    ```

    如果识别与`VOICE_SETTINGS`意图代码相关，则将`bestMatch`参数传递给`readPreferences`参数，该参数加载并设置所有带有预设设定点的温度条。设置`mEditingPreset`变量，以便在保存过程中我们可以重用预设名称。

我们已经对`Settings`活动做了所有必要的更改，现在可以在`Overview`活动中使用语音识别来加载和设置激活的预设。

## 使用语音识别来更改激活的预设

既然用户可以存储不同的预设，我们就必须提供一种在`Overview`活动中更改激活的设定点的方法。之前，我们添加了一个显示当前预设名称的`TextView`类；为了保持界面简洁，我们可以使用这个组件来启动语音识别。用户可以通过当前流程更改激活的预设：

1.  当用户点击**TextView**选项时，系统应启动语音识别以获取预设名称。

1.  如果找到了预设，应该用用户选择的预设替换激活的预设，并更新`Overview`的温度条。

1.  如果找不到预设，则不应有任何反应。

要实现上述交互流程，请按照以下步骤进行：

1.  正如我们对`Settings`活动所做的那样，从`Overview`类扩展`RecognizerActivity`类，如下面的代码片段所示：

    ```kt
    public class Overview extends RecognizerActivity implements OnDataChangeListener {
      //...
    }
    ```

1.  声明我们将用来识别和处理识别结果的意图请求代码。在类的顶部，添加高亮代码：

    ```kt
    public class Overview extends RecognizerActivity implements OnDataChangeListener {
      public static final int VOICE_PRESET = 1000;
      private AdkManager mAdkManager;
      //...
    }
    ```

1.  在类的底部，添加一个方法来启动预设名称识别：

    ```kt
    public void changePreset(View v) {
      startRecognition("Choose the current preset", VOICE_PRESET);
    }
    ```

1.  实现`onRecognitionDone()`回调以处理识别意图返回的结果。在这个方法中，我们调用`setPreset()`成员函数来更新激活的预设并加载温度设定点，如果找到了给定的预设。在类的底部，添加以下代码：

    ```kt
    @Override
    public void onRecognitionDone(int requestCode, String bestMatch) {
      if (requestCode == VOICE_PRESET) {
        setPreset(bestMatch);
      }
    }
    ```

1.  实现`setPreset()`方法来处理最佳识别结果。在类的底部，添加以下代码：

    ```kt
    private void setPreset(String name) {
      ArrayList<Integer> values = Preset.get(this, name);
      if (values.size() > 0) {
        Preset.setCurrent(this, name);
        readPreferences();
      }
    }
    ```

1.  将启动语音识别的`changePreset()`方法与`TextView`组件连接起来。在`res/layout/`下的`activity_overview.xml`文件中，通过高亮代码使`current_preset`视图可点击：

    ```kt
    <TextView
      android:id="@+id/current_preset"
      android:clickable="true"
      android:onClick="changePreset"
      android:text="NO PRESET ACTIVATED"
      android:gravity="center"
      android:textColor="@color/coral_red"
      android:textSize="@dimen/text_title"
      android:layout_width="0dp"
      android:layout_weight="2"
      android:layout_height="match_parent" />
    ```

通过这一节，我们创建了一个抽象层来通过 Android 意图处理语音识别，并且更新了`Settings`和`Overview`活动以使用它。现在我们可以上传 Chronotherm 应用程序，并再次使用带有预设和语音识别功能的应用程序。

# 改进用户与语音合成的交互

即使 Chronotherm 应用程序工作正常，我们至少还有一件事要做：提供适当的反馈，让用户知道已采取的行动。实际上，这两个活动都没有提供关于识别输入的任何视觉反馈；因此，我们决定在初始设计中引入语音合成 API。

因为我们希望在不同的活动中共享合成过程，我们可以创建一个管理器，通过共同的初始化抽象合成 API。这个想法是提供一个类，它公开了一个方法，使用给定的字符串开始语音识别；我们按照以下步骤实现它：

1.  在`voice`包内创建`VoiceManager`类。

1.  使用以下代码初始化类：

    ```kt
    public class VoiceManager implements TextToSpeech.OnInitListener {
      private TextToSpeech mTts;
      //...
    }
    ```

    这个类实现了`OnInitListener`接口，该接口定义了在初始化`TextToSpeech`引擎后应调用的回调。我们存储当前的`TextToSpeech`实例，我们将在以下代码段中使用它作为一个变量。

1.  重写`onInit()`方法，使其在`TextToSpeech`实例服务初始化成功时设置美国地区：

    ```kt
    @Override
    public void onInit(int status) {
      if (status == TextToSpeech.SUCCESS) {
        mTts.setLanguage(Locale.US); 
      }
    }
    ```

1.  添加类构造函数，在其中使用给定的活动`Context`初始化文本转语音服务。在类内部，编写以下代码：

    ```kt
    public VoiceManager(Context ctx) {
      mTts = new TextToSpeech(ctx, this);
    }
    ```

1.  实现一个`speak()`方法，通过在类底部添加以下代码，将给定文本代理给`TextToSpeech`实例：

    ```kt
    public void speak(String textToSay) {
      mTts.speak(textToSay, TextToSpeech.QUEUE_ADD, null);
    }
    ```

    `TextToSpeech.speak`方法采用队列策略使其异步化。调用该方法时，合成请求会被添加到队列中，并在服务初始化后进行处理。队列模式可以作为 speak 方法的第二个参数进行定义。我们可以在以下链接找到关于文本转语音服务的更多信息：

    [`developer.android.com/reference/android/speech/tts/TextToSpeech.html`](http://developer.android.com/reference/android/speech/tts/TextToSpeech.html)

## 向用户提供反馈

我们现在应该调整我们的活动以使用前面类中实现的简单抽象。我们从`Overview`活动开始，初始化`VoiceManager`实例，并在`setPreset()`方法中使用它，以提供是否找到识别的预设的正确反馈。要在`Overview`活动中使用合成 API，请执行以下步骤：

1.  在类顶部，在变量声明之间添加高亮显示的代码：

    ```kt
    private DataReader mReader;
    private VoiceManager mVoice;

    ```

1.  在`onCreate()`回调的底部，按以下代码片段所示初始化`VoiceManager`实例：

    ```kt
    mReader = new DataReader(mAdkManager, this, this);
    mVoice = new VoiceManager(this);

    ```

1.  使用高亮显示的代码更新`setPreset()`方法，使其在预设激活期间调用合成 API 以提供反馈：

    ```kt
    private void setPreset(String name) {
      ArrayList<Integer> values = Preset.get(this, name);
      String textToSay;
      if (values.size() > 0) {
        Preset.setCurrent(this, name);
        readPreferences();
        textToSay = "Activated preset " + name;
      }
      else {
        textToSay = "Preset " + name + " not found!";
      }
      mVoice.speak(textToSay);
    }
    ```

原型几乎完成，我们只需要对`Settings`活动重复前面的步骤。在这个活动中，我们应该初始化`VoiceManager`参数，并在`onRecognitionDone()`回调中使用合成 API。在那里，我们应该告知用户识别的预设是什么，以及根据检索到的设定点，它是将被创建还是编辑。要在`Settings`活动中使用合成 API，请执行以下步骤：

1.  在类的顶部，按照高亮代码声明`VoiceManager`变量：

    ```kt
    private String mEditingPreset;
    private VoiceManager mVoice;

    ```

1.  在`onCreate()`回调的底部，初始化`VoiceManager`实例：

    ```kt
    mVoice = new VoiceManager(this);
    startRecognition("Choose the preset you want to edit", VOICE_SETTINGS);
    ```

1.  更新`onRecognitionDone()`回调，使其调用合成 API 以提供适当的反馈：

    ```kt
    @Override
    public void onRecognitionDone(int requestCode, String bestMatch) {
      if (requestCode == VOICE_SETTINGS) {
        String textToSay;
        boolean result = readPreferences(bestMatch);
        if (result) {
          textToSay = "Editing preset " + bestMatch;
        }
     else {
          textToSay = "Creating preset " + bestMatch;
        }
        mEditingPreset = bestMatch;
        mVoice.speak(textToSay);
      }
    }
    ```

我们已经完成了对原型的增强，加入了语音识别和合成功能。最后缺失的任务是再次上传应用程序，并检查一切是否如预期般工作。然后我们可以将 Chronotherm 应用程序在`app/build.gradle`文件中更新为`0.2.0`版本。

# 总结

在本章中，我们通过少量工作成功引入了许多功能。我们学会了如何利用语音识别和合成，制作一个精简且快速的用户界面。

我们开始了一段旅程，创造了一种新的存储用户预设的方法，这需要对活动和`SensorThread`温度检查进行重构。我们继续进行语音识别的第一个实现，并且为了简化我们的工作，我们创建了一个从`Settings`和`Overview`活动扩展的通用活动类。这使得我们能够抽象出一些常见行为，便于在不同的代码部分调用识别意图。

作为最后一步，我们准备了语音合成管理器，以便轻松使用 Android 的文本到语音引擎。实际上，我们使用这个组件在识别过程后，当用户更改设置和当前激活的预设时提供反馈。

在下一章中，我们将为 Chronotherm 应用程序添加网络功能，以便它能够检索天气预报数据；使用这些信息，我们将制作一个稍微更好的算法来决定是否打开或关闭我们的锅炉。
