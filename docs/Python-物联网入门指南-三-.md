# Python 物联网入门指南（三）

> 原文：[`zh.annas-archive.org/md5/4fe4273add75ed738e70f3d05e428b06`](https://zh.annas-archive.org/md5/4fe4273add75ed738e70f3d05e428b06)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：构建人脸检测器和人脸识别应用程序

本章介绍以下主题：

+   人脸识别系统简介

+   构建人脸检测器应用程序

+   构建人脸识别应用程序

+   人脸识别系统的应用

# 介绍

近年来，人脸识别已成为最热门的研究领域之一。人脸识别系统是一种具有检测和识别人脸能力的计算机程序。为了识别一个人，它考虑他们独特的面部特征。最近，它已被应用于多个安全和监控设施，以确保高风险区域、住宅区、私人和公共建筑等的安全。

# 构建人脸检测器应用程序

在本节中，我们讨论了如何从网络摄像头图像中检测人脸。需要将 USB 网络摄像头连接到树莓派 3 上，以实现实时人脸检测。

# 如何做...

1.  导入必要的包：

```py
import cv2 
import numpy as np 
```

1.  加载人脸级联文件：

```py
frontalface_cascade= cv2.CascadeClassifier('haarcascade_frontalface_alt.xml') 
```

1.  检查人脸级联文件是否已加载：

```py
if frontalface_cascade.empty(): 
  raiseIOError('Unable to load the face cascade classifier xml file') 
```

1.  初始化视频捕获对象：

```py
capture = cv2.VideoCapture(0) 
```

1.  定义缩放因子：

```py
scale_factor = 0.5 
```

1.  直到按下*Esc*键为止执行操作：

```py
# Loop until you hit the Esc key 
while True: 
```

1.  捕获当前帧并调整大小：

```py
  ret, frame = capture.read() 
  frame = cv2.resize(frame, None, fx=scale_factor, fy=scale_factor,  
            interpolation=cv2.INTER_AREA) 
```

1.  将图像帧转换为灰度：

```py
  gray_image = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) 
```

1.  在灰度图像上运行人脸检测器：

```py
  face_rectangle = frontalface_cascade.detectMultiScale(gray_image, 1.3, 5)
```

1.  绘制矩形框：

```py
  for (x,y,w,h) in face_rectangle: 
    cv2.rectangle(frame, (x,y), (x+w,y+h), (0,255,0), 3) 
```

1.  显示输出图像：

```py
    cv2.imshow('Face Detector', frame) 
```

1.  检查是否按下了*Esc*键以终止操作：

```py
  a = cv2.waitKey(1) 
  if a == 10: 
    break 
```

1.  停止视频捕获并终止操作：

```py
capture.release() 
cv2.destroyAllWindows() 
```

人脸检测系统中获得的结果如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/5cb83a55-bccc-4135-b2ec-90bc2564dc2d.png)

# 构建人脸识别应用程序

人脸识别是在人脸检测之后执行的一种技术。检测到的人脸与数据库中存储的图像进行比较。它从输入图像中提取特征并将其与数据库中存储的人脸特征进行匹配。

# 如何做...

1.  导入必要的包：

```py
import cv2 
import numpy as np   
from sklearn import preprocessing 
```

1.  加载编码和解码任务运算符：

```py
class LabelEncoding(object): 
  # Method to encode labels from words to numbers 
  def encoding_labels(self, label_wordings): 
    self.le = preprocessing.LabelEncoder() 
    self.le.fit(label_wordings) 
```

1.  为输入标签实现从单词到数字的转换：

```py
  def word_to_number(self, label_wordings): 
    return int(self.le.transform([label_wordings])[0]) 
```

1.  将输入标签从数字转换为单词：

```py
  def number_to_word(self, label_number): 
    return self.le.inverse_transform([label_number])[0] 
```

1.  从输入路径提取图像和标签：

```py
def getting_images_and_labels(path_input): 
  label_wordings = [] 
```

1.  迭代输入路径的过程并附加文件：

```py
  for roots, dirs, files in os.walk(path_input): 
    for fname in (x for x in files if x.endswith('.jpg')): 
      fpath = os.path.join(roots, fname) 
      label_wordings.append(fpath.split('/')[-2])
```

1.  初始化变量并解析输入寄存器：

```py
  images = [] 
  le = LabelEncoding() 
  le.encoding_labels(label_wordings) 
  labels = [] 
  # Parse the input directory 
  for roots, dirs, files in os.walk(path_input): 
    for fname in (x for x in files if x.endswith('.jpg')): 
      fpath = os.path.join(roots, fname) 
```

1.  读取灰度图像：

```py
      img = cv2.imread(fpath, 0)  
```

1.  提取标签：

```py
      names = fpath.split('/')[-2] 
```

1.  执行人脸检测：

```py
      face = faceCascade.detectMultiScale(img, 1.1, 2, minSize=(100,100)) 
```

1.  使用面部矩形迭代该过程：

```py
      for (x, y, w, h) in face: 
        images.append(img[y:y+h, x:x+w]) 
        labels.append(le.word_to_number(names)) 
  return images, labels, le 
if __name__=='__main__': 
  path_cascade = "haarcascade_frontalface_alt.xml" 
  train_img_path = 'faces_dataset/train' 
  path_img_test = 'faces_dataset/test' 
```

1.  加载人脸级联文件：

```py
  faceCascade = cv2.CascadeClassifier(path_cascade) 
```

1.  使用局部二值模式初始化人脸检测：

```py
  face_recognizer = cv2.createLBPHFaceRecognizer()
```

1.  从训练人脸数据集中提取人脸特征：

```py
  imgs, labels, le = getting_images_and_labels(train_img_path) 
```

1.  训练人脸检测系统：

```py
  print "nTraining..." 
  face_recognizer.train(imgs, np.array(labels)) 
```

1.  测试人脸检测系统：

```py
  print 'nPerforming prediction on test images...' 
  flag_stop = False 
  for roots, dirs, files in os.walk(path_img_test): 
    for fname in (x for x in files if x.endswith('.jpg')): 
      fpath = os.path.join(roots, fname) 
```

1.  验证人脸识别系统：

```py
      predicting_img = cv2.imread(fpath, 0) 
            # Detect faces 
      face = faceCascade.detectMultiScale(predicting_img, 1.1,  
                    2, minSize=(100,100)) 
            # Iterate through face rectangles 
      for (x, y, w, h) in face: 
        # Predict the output 
        index_predicted, config = face_recognizer.predict( 
predicting_img[y:y+h, x:x+w]) 
        # Convert to word label 
        person_predicted = le.number_to_word(index_predicted) 
        # Overlay text on the output image and display it 
        cv2.putText(predicting_img, 'Prediction: ' +  person_predicted,  
                        (10,60), cv2.FONT_HERSHEY_SIMPLEX, 2, (255,255,255), 6) 
        cv2.imshow("Recognizing face", predicting_img) 
      a = cv2.waitKey(0) 
      if a == 27: 
        flag = True 
        break 
    if flag_stop: 
      break 
```

这里显示了人脸识别的输出结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/7526565a-5ec3-4065-a9df-d18c86f90bf5.png)

# 工作原理...

人脸识别系统广泛用于实现个人安全系统。读者可以参考文章*基于 OpenCV 的人脸检测系统*，网址为[`ieeexplore.ieee.org/document/6242980/`](http://ieeexplore.ieee.org/document/6242980/)。

另请参阅*用于实时人脸检测系统的人脸检测算法研究*，网址为[`ieeexplore.ieee.org/document/5209668`](http://ieeexplore.ieee.org/document/5209668)。

# 另请参阅

请参考以下文章：

+   [`www.ex-sight.com/technology.htm`](http://www.ex-sight.com/technology.htm)

+   [`www.eurotech.com/en/products/devices/face+recognition+systems`](https://www.eurotech.com/en/products/devices/face+recognition+systems)

+   [`arxiv.org/ftp/arxiv/papers/1403/1403.0485.pdf`](https://arxiv.org/ftp/arxiv/papers/1403/1403.0485.pdf)

# 人脸识别系统的应用

人脸识别广泛应用于安全、医疗保健和营销领域。各行业正在利用深度学习开发新型人脸识别系统，用于识别欺诈、区分人脸和照片之间的差异等。在医疗保健领域，人脸识别结合其他计算机视觉算法用于检测面部皮肤疾病。


# 第七章：使用 Python 驱动硬件

在本章中，我们将涵盖以下主题：

+   控制 LED

+   响应按钮

+   控制关机按钮

+   GPIO 键盘输入

+   多路复用彩色 LED

+   使用视觉持久性编写消息

# 介绍

树莓派计算机的一个关键特性是它能够直接与其他硬件进行接口。树莓派上的通用输入/输出（GPIO）引脚可以控制各种低级电子设备，从发光二极管（LED）到开关、传感器、电机、伺服和额外的显示器。

本章将重点介绍如何连接树莓派与一些简单的电路，并掌握使用 Python 来控制和响应连接的组件。

树莓派硬件接口由板子一侧的 40 个引脚组成。

GPIO 引脚及其布局将根据您拥有的特定型号略有不同。

树莓派 3、树莓派 2 和树莓派 B+都具有相同的 40 针布局。

树莓派 1 代老款（非 plus 型号）有一个 26 针的引脚，与新款模型的 1-26 针相同。

树莓派 2、树莓派 B+和树莓派 Plus GPIO 引脚（引脚功能）

连接器的布局如上图所示；引脚编号从 GPIO 引脚的引脚 1 开始。

引脚 1 位于最靠近 SD 卡的一端，如下图所示：

树莓派 GPIO 引脚位置

在使用 GPIO 引脚时应当小心，因为它还包括电源引脚（3V3 和 5V），以及地线（GND）引脚。所有的 GPIO 引脚都可以用作标准 GPIO，但其中一些还具有特殊功能；这些被标记并用不同颜色突出显示。

工程师通常使用 3V3 标记来指定原理图中的值，以避免使用可能被忽略的小数位（使用 33V 而不是 3.3V 会对电路造成严重损坏）。同样的方法也可以应用于其他组件的值，比如电阻，例如，1.2K 欧姆可以写成 1K2 欧姆。

TX 和 RX 引脚用于串行通信，借助电压级转换器，信息可以通过串行电缆传输到另一台计算机或设备。

我们还有 SDA 和 SCL 引脚，它们能够支持一种名为 I²C 的双线总线通信协议（树莓派 3 和 Plus 板上有两个 I²C 通道：通道 1 ARM，用于通用用途，通道 0 VC，通常用于识别 HAT 模块上连接的硬件）。还有 SPI MOSI、SPI MISO、SPI SCLK、SPI CE0 和 SPI CE1 引脚，支持另一种名为 SPI 的高速数据总线协议。最后，我们有 PWM0/1 引脚，允许生成脉冲宽度调制信号，对于伺服和生成模拟信号非常有用。

然而，在本章中，我们将专注于使用标准的 GPIO 功能。GPIO 引脚布局如下图所示：

树莓派 GPIO 引脚（GPIO.BOARD 和 GPIO.BCM）

树莓派 Rev 2（2014 年 7 月之前）与树莓派 2 GPIO 布局相比有以下不同：

+   26 个 GPIO 引脚的引脚头（匹配前 26 个引脚）。

+   引脚头旁边的另一组八个孔（P5）。详细信息如下：

树莓派 Rev 2 P5 GPIO 引脚

+   原始的树莓派 Rev 1（2012 年 10 月之前）总共只有 26 个 GPIO 引脚（匹配当前树莓派的前 26 个引脚），除了以下细节：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/ec7fdb0c-b61f-4108-b924-a6162d59bf0e.png)树莓派 Rev 1 GPIO 引脚头的差异

`RPi.GPIO`库可以使用两种系统之一引用树莓派上的引脚。中间显示的数字是引脚的物理位置，也是在**GPIO.BOARD**模式下`RPi.GPIO`库引用的数字。外部的数字（**GPIO.BCM**）是处理器物理端口的实际引用数字，指示哪些引脚被连接（这就是为什么它们没有特定的顺序）。当模式设置为**GPIO.BCM**时使用它们，并且它们允许控制 GPIO 引脚以及连接到其他 GPIO 线的任何外围设备。这包括 BCM GPIO 4 上的附加摄像头上的 LED 和板上的状态 LED。但是，这也可能包括用于读/写 SD 卡的 GPIO 线，如果干扰会导致严重错误。

如果您使用其他编程语言访问 GPIO 引脚，编号方案可能会有所不同，因此如果您了解 BCM GPIO 引用，将会很有帮助，它们指的是处理器的物理 GPIO 端口。

请务必查看附录*硬件和软件清单*，其中列出了本章中使用的所有物品以及您可以从哪里获得它们。

# 控制 LED

硬件上的`hello world`等同于 LED 闪烁，这是一个很好的测试，可以确保一切正常工作，并且你已经正确地连接了它。为了让它更有趣，我建议使用**红色、蓝色和绿色**（RGB）LED，但如果你只有单独的 LED 也可以。

# 准备工作

你将需要以下设备：

+   4 x 杜邦母对公补丁线

+   迷你面包板（170 个连接点）或更大的面包板

+   RGB LED（共阴）/3 个标准 LED（最好是红色、绿色和蓝色）

+   面包板线（实心线）

+   3 x 470 欧姆电阻

前面提到的每个组件成本都不会太高，并且可以在其他项目中重复使用。面包板是一个特别有用的物品，可以让你在不需要焊接的情况下尝试自己的电路：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/f9a79a3b-7ca0-4c4e-b4e6-a4d6ff9c69fb.png)RGB LED、标准 LED 和 RGB 电路的图表

以下图表显示了面包板电路：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/88293cf3-b0ab-45fc-999f-af4c445e2e1d.png)连接到 GPIO 引脚的 RGB LED/标准 LED 的接线图有几种不同类型的 RGB LED 可用，因此请检查您组件的数据表以确认引脚顺序和类型。有些是 RGB 的，所以确保你按照相应的方式连接引脚，或者在代码中调整`RGB_`引脚设置。你也可以获得共阳极变种，这将需要阳极连接到 3V3（GPIO 引脚 1）才能点亮（它们还需要将`RGB_ENABLE`和`RGB_DISABLE`设置为`0`和`1`）。

本书的面包板和组件图是使用一个名为**Fritzing**（[www.fritzing.org](http://www.fritzing.org)）的免费工具创建的；它非常适合规划您自己的树莓派项目。

# 如何做...

1.  创建`ledtest.py`脚本如下：

```py
#!/usr/bin/python3 
#ledtest.py 
import time 
import RPi.GPIO as GPIO 
# RGB LED module 
#HARDWARE SETUP 
# GPIO 
# 2[======XRG=B==]26[=======]40 
# 1[=============]25[=======]39 
# X=GND R=Red G=Green B=Blue  
#Setup Active States 
#Common Cathode RGB-LED (Cathode=Active Low) 
RGB_ENABLE = 1; RGB_DISABLE = 0 

#LED CONFIG - Set GPIO Ports 
RGB_RED = 16; RGB_GREEN = 18; RGB_BLUE = 22 
RGB = [RGB_RED,RGB_GREEN,RGB_BLUE] 

def led_setup(): 
  #Setup the wiring 
  GPIO.setmode(GPIO.BOARD) 
  #Setup Ports 
  for val in RGB: 
    GPIO.setup(val,GPIO.OUT) 

def main(): 
  led_setup() 
  for val in RGB: 
    GPIO.output(val,RGB_ENABLE) 
    print("LED ON") 
    time.sleep(5) 
    GPIO.output(val,RGB_DISABLE) 
    print("LED OFF") 

try: 
  main() 
finally: 
  GPIO.cleanup() 
  print("Closed Everything. END") 
#End
```

1.  `RPi.GPIO`库将需要`sudo`权限来访问 GPIO 引脚硬件，因此您需要使用以下命令运行脚本：

```py
sudo python3 ledtest.py  
```

运行脚本时，您应该看到 LED 的红色、绿色和蓝色部分（或者如果您使用单独的 LED，则分别点亮）。如果没有，请仔细检查您的接线或确认 LED 是否正常工作，方法是暂时将红色、绿色或蓝色线连接到 3V3 引脚（GPIO 引脚 1）。

大多数与硬件相关的脚本都需要`sudo`命令，因为用户通常不会直接在这么低的层次上控制硬件。例如，设置或清除作为 SD 卡控制器一部分的控制引脚可能会损坏正在写入的数据。因此，出于安全目的，需要超级用户权限，以防止程序意外（或恶意）使用硬件。

# 工作原理...

要使用 Python 访问 GPIO 引脚，我们导入`RPi.GPIO`库，该库允许通过模块函数直接控制引脚。我们还需要`time`模块来暂停程序一定数量的秒。

然后，我们为 LED 的接线和激活状态定义值（请参阅本食谱的*有更多...*部分中的*控制 GPIO 电流*段）。

在程序使用 GPIO 引脚之前，我们需要通过指定编号方法（`GPIO.BOARD`）和方向（`GPIO.OUT`或`GPIO.IN`）来设置它们（在这种情况下，我们将所有 RGB 引脚设置为输出）。如果引脚配置为输出，我们将能够设置引脚状态；同样，如果它配置为输入，我们将能够读取引脚状态。

接下来，我们使用`GPIO.ouput()`来控制引脚，指定 GPIO 引脚的编号和我们希望它处于的状态（`1` = 高/开启，`0` = 低/关闭）。我们打开每个 LED，等待五秒，然后关闭它。

最后，我们使用`GPIO.cleanup()`将 GPIO 引脚恢复到它们的原始默认状态，并释放对引脚的控制，以供其他程序使用。

# 有更多...

在树莓派上使用 GPIO 引脚必须小心，因为这些引脚直接连接到树莓派的主处理器，没有额外的保护。必须小心使用，因为任何错误的接线可能会损坏树莓派处理器，并导致其完全停止工作。

或者，您可以使用许多直接插入 GPIO 引脚排针的模块之一（减少接线错误的机会）：

例如，Pi-Stop 是一个简单的预制 LED 板，模拟了一组交通信号灯，旨在成为那些对控制硬件感兴趣但又想避免损坏树莓派的人的一个过渡阶段。掌握了基础知识后，它也是一个出色的指示器，有助于调试。

只需确保您在`ledtest.py`脚本中更新`LED CONFIG`引脚引用，以引用您使用的硬件的引脚布局和位置。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/ad34ee37-0365-4a28-a71c-578b0daa28e3.png)

请参阅附录中的*硬件和软件清单*，了解树莓派硬件零售商的清单。

# 控制 GPIO 电流

每个 GPIO 引脚在烧毁之前只能处理一定电流（单个引脚最大 16mA，总共 30mA），同样，RGB LED 的电流应限制在 100mA 以下。通过在 LED 之前或之后添加电阻，我们将能够限制通过 LED 的电流并控制其亮度（更大的电流将使 LED 更亮）。

由于我们可能希望同时点亮多个 LED，因此我们通常会尽量将电流设置得尽可能低，同时仍然提供足够的功率点亮 LED。

我们可以使用欧姆定律来告诉我们需要多少电阻来提供特定的电流。该定律如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/f3fc16b6-3b93-46ac-9491-565b179ecd6a.png)欧姆定律：电路中电流、电阻和电压之间的关系

我们将以最小电流（3mA）和最大电流（16mA）为目标，同时仍然从每个 LED 产生相当明亮的光。为了获得 RGB LED 的平衡输出，我测试了不同的电阻，直到它们提供了接近白光（通过卡片查看）。每个 LED 选择了 470 欧姆的电阻（您的 LED 可能略有不同）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/64bf4bbc-c955-45b6-9567-4372306aa5d1.png)需要电阻器来限制通过 LED 的电流

电阻器上的电压等于 GPIO 电压（**Vgpio** = 3.3V）减去特定 LED 的电压降（**Vfwd**）；然后我们可以使用这个电阻来计算每个 LED 使用的电流，如下面的公式所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/6a89db2a-ff7b-4579-b310-230c7c9c9ca4.png)我们可以计算每个 LED 的电流

# 响应按钮

许多使用树莓派的应用程序要求在不需要连接键盘和屏幕的情况下激活操作。 GPIO 引脚为树莓派提供了一种优秀的方式，使其可以通过您自己的按钮和开关进行控制，而无需鼠标/键盘和屏幕。

# 准备工作

您将需要以下设备：

+   2 x DuPont 母对公跳线

+   迷你面包板（170 个连接点）或更大的面包板

+   按钮开关（瞬时闭合）或导线连接以打开/关闭电路

+   面包板导线（实心线）

+   1K 欧姆电阻器

开关如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/325f711c-c617-4bcb-b66a-1b17ab3f2080.png)按钮开关和其他类型的开关以下示例中使用的开关是**单极，单刀**（**SPST**），瞬时闭合，按钮开关。**单极**（**SP**）意味着有一组使连接的触点。在这里使用的按钮开关的情况下，每侧的腿与中间的单极开关连接在一起。**双极**（**DP**）开关的作用就像单极开关，只是两侧在电上是分开的，允许您同时打开/关闭两个独立的组件。

**单刀**（**ST**）意味着开关将仅在一个位置进行连接；另一侧将保持开放。**双刀**（**DT**）意味着开关的两个位置将连接到不同的部分。

**瞬时闭合**意味着按下按钮时将关闭开关，并在释放时自动打开。**锁定**按钮开关将保持关闭状态，直到再次按下。

# 尝试使用树莓派的扬声器或耳机

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/c54871b1-71d9-4932-9f4b-d212a53578d3.png)按钮电路的布局

在此示例中，我们将使用声音，因此您还需要将扬声器或耳机连接到树莓派的音频插孔。

您需要使用以下命令安装名为`flite`的程序，这将让我们让树莓派说话：

```py
sudo apt-get install flite  
```

安装后，您可以使用以下命令进行测试：

```py
sudo flite -t "hello I can talk"  
```

如果太安静（或太吵），您可以使用以下命令调整音量（0-100％）：

```py
amixer set PCM 100%  
```

# 如何做...

创建`btntest.py`脚本如下：

```py
#!/usr/bin/python3 
#btntest.py 
import time 
import os 
import RPi.GPIO as GPIO 
#HARDWARE SETUP 
# GPIO 
# 2[==X==1=======]26[=======]40 
# 1[=============]25[=======]39 
#Button Config 
BTN = 12 

def gpio_setup(): 
  #Setup the wiring 
  GPIO.setmode(GPIO.BOARD) 
  #Setup Ports 
  GPIO.setup(BTN,GPIO.IN,pull_up_down=GPIO.PUD_UP) 

def main(): 
  gpio_setup() 
  count=0 
  btn_closed = True 
  while True: 
    btn_val = GPIO.input(BTN) 
    if btn_val and btn_closed: 
       print("OPEN") 
       btn_closed=False 
    elif btn_val==False and btn_closed==False: 
       count+=1 
       print("CLOSE %s" % count) 
       os.system("flite -t '%s'" % count) 
       btn_closed=True 
    time.sleep(0.1) 

try: 
  main() 
finally: 
  GPIO.cleanup() 
  print("Closed Everything. END") 
#End 
```

# 它是如何工作的...

与上一个示例一样，我们根据需要设置 GPIO 引脚，但这次是作为输入，并且还启用了内部上拉电阻器（有关更多信息，请参阅本示例的*更多内容...*部分中的*上拉和下拉电阻器电路*）使用以下代码：

```py
GPIO.setup(BTN,GPIO.IN,pull_up_down=GPIO.PUD_UP) 
```

在设置了 GPIO 引脚之后，我们创建一个循环，将不断检查`BTN`的状态，使用`GPIO.input()`。如果返回的值为`false`，则表示通过开关将引脚连接到 0V（地），我们将使用`flite`每次按下按钮时为我们大声计数。

由于我们在`try`/`finally`条件中调用了主函数，即使我们使用*Ctrl* + *Z*关闭程序，它仍将调用`GPIO.cleanup()`。

我们在循环中使用短延迟；这可以确保忽略开关上的接触产生的任何噪音。这是因为当我们按下按钮时，按下或释放时并不总是完美接触，如果我们再次按下它，可能会产生多个触发。这被称为**软件去抖动**；我们在这里忽略了信号中的弹跳。

# 更多内容...

树莓派 GPIO 引脚必须小心使用；用于输入的电压应该是

在特定范围内，并且从中抽取的任何电流应该最小化使用

保护电阻。

# 安全电压

我们必须确保只连接在 0（地）和 3V3 之间的输入。一些处理器使用 0V 到 5V 之间的电压，因此需要额外的组件才能安全地与它们接口。除非确定安全，否则永远不要连接使用 5V 的输入或组件，否则会损坏树莓派的 GPIO 端口。

# 上拉和下拉电阻电路

先前的代码设置了 GPIO 引脚使用内部上拉电阻。如果 GPIO 引脚上没有上拉电阻（或下拉电阻），电压可以在 3V3 和 0V 之间自由浮动，实际逻辑状态保持不确定（有时为 1，有时为 0）。

树莓派的内部上拉电阻为 50K 欧姆至 65K 欧姆，下拉电阻为 50K 欧姆至 65K 欧姆。外部上拉/下拉电阻通常用于 GPIO 电路（如下图所示），通常使用 10K 欧姆或更大的电阻出于类似的原因（当它们不活动时提供非常小的电流吸收）。

上拉电阻允许通过 GPIO 引脚流动少量电流，并且在开关未按下时提供高电压。当按下开关时，小电流被流向 0V 的大电流所取代，因此我们在 GPIO 引脚上得到低电压。开关在按下时为活动低电平和逻辑 0。它的工作原理如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/29c4c4eb-9bc8-4f96-bd07-7c8206af9a32.png)上拉电阻电路

下拉电阻的工作方式相同，只是开关为活动高电平（按下时 GPIO 引脚为逻辑 1）。它的工作原理如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/b8708774-f896-4447-acc1-a829863676d1.png)下拉电阻电路

# 保护电阻

除了开关外，电路还包括与开关串联的电阻，以保护 GPIO 引脚，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/f47a0106-2712-472d-a88b-7efea679d893.png)GPIO 保护限流电阻

保护电阻的目的是保护 GPIO 引脚，如果它被意外设置为输出而不是输入。例如，假设我们的开关连接在 GPIO 和地之间。现在 GPIO 引脚被设置为输出并打开（驱动到 3V3），一旦我们按下开关，没有电阻的情况下，GPIO 引脚将直接连接到 0V。 GPIO 仍然会尝试将其驱动到 3V3；这将导致 GPIO 引脚烧毁（因为它将使用太多电流来驱动引脚到高状态）。如果我们在这里使用 1K 欧姆电阻，引脚可以使用可接受的电流驱动高（I = V/R = 3.3/1K = 3.3 毫安）。

# 受控关机按钮

树莓派应该始终正确关机，以避免 SD 卡损坏（在对卡进行写操作时断电）。如果您没有连接键盘或屏幕（可能正在运行自动化程序或通过网络远程控制），这可能会造成问题，因为您无法输入命令或查看您正在做什么。通过添加我们自己的按钮和 LED 指示灯，我们可以轻松地命令关机和重启，然后再次启动以指示系统处于活动状态。

# 准备工作

您将需要以下设备：

+   3 x DuPont 母对公跳线

+   迷你面包板（170 个连接点）或更大的面包板

+   按钮开关（瞬时闭合）

+   通用 LED

+   2 x 470 欧姆电阻

+   面包板导线（实心）

关机电路的整个布局将如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/32384f24-fc03-40a6-953b-a4e9a263e4ab.png)受控关机电路布局

# 如何操作...

1.  创建`shtdwn.py`脚本如下：

```py
#!/usr/bin/python3 
#shtdwn.py 
import time 
import RPi.GPIO as GPIO 
import os 

# Shutdown Script 
DEBUG=True #Simulate Only 
SNDON=True 
#HARDWARE SETUP 
# GPIO 
# 2[==X==L=======]26[=======]40 
# 1[===1=========]25[=======]39 

#BTN CONFIG - Set GPIO Ports 
GPIO_MODE=GPIO.BOARD 
SHTDWN_BTN = 7 #1 
LED = 12       #L 

def gpio_setup(): 
  #Setup the wiring 
  GPIO.setmode(GPIO_MODE) 
  #Setup Ports 
  GPIO.setup(SHTDWN_BTN,GPIO.IN,pull_up_down=GPIO.PUD_UP) 
  GPIO.setup(LED,GPIO.OUT) 

def doShutdown(): 
  if(DEBUG):print("Press detected") 
  time.sleep(3) 
  if GPIO.input(SHTDWN_BTN): 
    if(DEBUG):print("Ignore the shutdown (<3sec)") 
  else: 
    if(DEBUG):print ("Would shutdown the RPi Now") 
    GPIO.output(LED,0) 
    time.sleep(0.5) 
    GPIO.output(LED,1) 
    if(SNDON):os.system("flite -t 'Warning commencing power down 3 2 1'") 
    if(DEBUG==False):os.system("sudo shutdown -h now") 
    if(DEBUG):GPIO.cleanup() 
    if(DEBUG):exit() 

def main(): 
  gpio_setup() 
  GPIO.output(LED,1) 
  while True: 
    if(DEBUG):print("Waiting for >3sec button press") 
    if GPIO.input(SHTDWN_BTN)==False: 
       doShutdown() 
    time.sleep(1) 

try: 
  main() 
finally: 
  GPIO.cleanup() 
  print("Closed Everything. END") 
#End
```

1.  要使这个脚本自动运行（一旦我们测试过它），我们可以将脚本放在`~/bin`中（如果只想复制它，可以使用`cp`而不是`mv`），并使用以下代码将其添加到`crontab`中：

```py
mkdir ~/bin 
mv shtdwn.py ~/bin/shtdwn.py  
crontab -e 
```

1.  在文件末尾，我们添加以下代码：

```py
@reboot sudo python3 ~/bin/shtdwn.py 
```

# 它是如何工作的...

这次，当我们设置 GPIO 引脚时，我们将与关机按钮连接的引脚定义为输入，与 LED 连接的引脚定义为输出。我们打开 LED 以指示系统正在运行。

通过将`DEBUG`标志设置为`True`，我们可以测试脚本的功能，而不会导致实际关闭（通过读取终端消息）；我们只需要确保在实际使用脚本时将`DEBUG`设置为`False`。

我们进入一个`while`循环，并每秒检查引脚，以查看 GPIO 引脚是否设置为`LOW`（即检查开关是否被按下）；如果是，我们就进入`doShutdown()`函数。

程序将等待三秒，然后再次测试按钮是否仍然被按下。如果按钮不再被按下，我们将返回到之前的`while`循环。但是，如果在三秒后它仍然被按下，程序将闪烁 LED 并触发关闭（还会使用`flite`提供音频警告）。

当我们对脚本的运行状态感到满意时，我们可以禁用`DEBUG`标志（将其设置为`False`），并将脚本添加到`crontab`中。`crontab`是一个在后台运行的特殊程序，允许我们在系统启动时（`@reboot`）安排程序和操作的特定时间、日期或周期性。这使得脚本可以在每次树莓派上电时自动启动。当我们按住关机按钮超过三秒时，它会安全地关闭系统并进入低功耗状态（LED 在此之前会关闭，表明很快就可以拔掉电源）。要重新启动树莓派，我们简单地拔掉电源；这将重新启动系统，当树莓派加载完成时，LED 会亮起。

# 还有更多...

我们可以通过添加额外的功能并利用额外的 GPIO 连接（如果可用）来进一步扩展这个示例。

# 重置和重新启动树莓派

树莓派上有用于安装复位标头的孔（在树莓派 3/2 上标有**RUN**，在树莓派 1 型 A 和 B Rev 2 上标有**P6**）。复位引脚允许使用按钮而不是每次都拔掉微型 USB 连接器来重置设备的电源：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/842a26a3-f0cc-4e68-993c-b5b9fda3ab38.png)树莓派复位标头-左边是树莓派 A/B 型（Rev2），右边是树莓派 3

要使用它，您需要将一根导线或引脚排焊接到树莓派上，并连接一个按钮（或每次在两个孔之间短暂触碰一根导线）。或者，我们可以扩展我们之前的电路，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/7f05b9ba-5dc4-4c35-a484-fbb8c67ff403.png)受控关闭电路布局和复位按钮

我们可以将这个额外的按钮添加到我们的电路中，它可以连接到复位标头（这是树莓派 3 上最靠近中间的孔，其他型号上最靠近边缘的孔）。当暂时将此引脚拉低连接到地（例如旁边的孔或 GPIO 标头的第 6 引脚等其他地点），将重置树莓派并允许它在关闭后再次启动。

# 添加额外功能

由于现在脚本一直监视关机按钮，我们可以同时添加额外的按钮/开关/跳线来监视。这将允许我们通过改变输入来触发特定程序或设置特定状态。以下示例允许我们轻松地在自动 DHCP 网络（默认网络设置）和使用直接 IP 地址之间进行切换，就像第一章“使用树莓派 3 计算机入门”中的“直接连接到笔记本电脑或计算机”配方中使用的那样。

将以下组件添加到上一个电路中：

+   一个 470 欧姆电阻

+   两个带跳线连接器的引脚头（或者，可选地，一个开关）

+   面包板导线（实心线）

在添加了上述组件之后，我们的受控关机电路现在如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/16390e01-579c-4baa-9947-a171dfde83ac.png)受控关机电路布局、复位按钮和跳线引脚

在上一个脚本中，我们添加了一个额外的输入来检测`LAN_SWA`引脚的状态（我们添加到电路中的跳线引脚），使用以下代码：

```py
LAN_SWA = 11    #2 
```

确保在`gpio_setup()`函数中设置为输入（带上拉电阻）使用以下代码：

```py
GPIO.setup(LAN_SWA,GPIO.IN,pull_up_down=GPIO.PUD_UP) 
```

添加一个新的功能来在 LAN 模式之间切换并读取新的 IP 地址。`doChangeLAN()`函数检查`LAN_SWA`引脚的状态是否自上次调用以来发生了变化，如果是，则将网络适配器设置为 DHCP，或者相应地设置直接 LAN 设置（如果可用，则使用`flite`来朗读新的 IP 设置）。最后，设置 LAN 为直接连接会导致 LED 在该模式激活时缓慢闪烁。使用以下代码来实现这一点：

```py
def doChangeLAN(direct): 
  if(DEBUG):print("Direct LAN: %s" % direct) 
  if GPIO.input(LAN_SWA) and direct==True: 
    if(DEBUG):print("LAN Switch OFF") 
    cmd="sudo dhclient eth0" 
    direct=False 
    GPIO.output(LED,1) 
  elif GPIO.input(LAN_SWA)==False and direct==False: 
    if(DEBUG):print("LAN Switch ON") 
    cmd="sudo ifconfig eth0 169.254.69.69" 
    direct=True 
  else: 
    return direct 
  if(DEBUG==False):os.system(cmd) 
  if(SNDON):os.system("hostname -I | flite") 
  return direct 
```

添加另一个函数`flashled()`，每次调用时切换 LED 的状态。该函数的代码如下：

```py
def flashled(ledon): 
  if ledon: 
    ledon=False 
  else: 
    ledon=True 
  GPIO.output(LED,ledon) 
  return ledon
```

最后，我们调整主循环，也调用`doChangeLAN()`，并使用结果决定是否使用`ledon`调用`flashled()`来跟踪 LED 的上一个状态。`main()`函数现在应该更新如下：

```py
def main(): 
  gpio_setup() 
  GPIO.output(LED,1) 
  directlan=False 
  ledon=True 
  while True: 
    if(DEBUG):print("Waiting for >3sec button press") 
    if GPIO.input(SHTDWN_BTN)==False: 
       doShutdown() 
    directlan= doChangeLAN(directlan) 
    if directlan: 
      flashled(ledon) 
    time.sleep(1) 
```

# GPIO 键盘输入

我们已经看到了如何监视 GPIO 上的输入来启动应用程序和控制树莓派；然而，有时我们需要控制第三方程序。使用`uInput`库，我们可以模拟键盘（甚至鼠标移动）来控制任何程序，使用我们自己的自定义硬件。

有关使用`uInput`的更多信息，请访问[`tjjr.fi/sw/python-uinput/`](http://tjjr.fi/sw/python-uinput/)。

# 准备工作

执行以下步骤安装`uInput`：

1.  首先，我们需要下载`uInput`。

您需要使用以下命令从 GitHub 下载`uInput` Python 库（约 50 KB）：

```py
wget https://github.com/tuomasjjrasanen/python-uinput/archive/master.zip
unzip master.zip

```

该库将解压缩到一个名为`python-uinput-master`的目录中。

1.  完成后，可以使用以下命令删除 ZIP 文件：

```py
rm master.zip  
```

1.  使用以下命令安装所需的软件包（如果已经安装了它们，`apt-get`命令将忽略它们）：

```py
sudo apt-get install python3-setuptools python3-dev
sudo apt-get install libudev-dev  
```

1.  使用以下命令编译和安装`uInput`：

```py
cd python-uinput-master
sudo python3 setup.py install  
```

1.  最后，使用以下命令加载新的`uinput`内核模块：

```py
sudo modprobe uinput  
```

为了确保在启动时加载，我们可以使用以下命令将`uinput`添加到`modules`文件中：

```py
sudo nano /etc/modules  
```

在文件中新建一行并保存（*Ctrl* + *X*, *Y*）。

1.  使用以下设备创建以下电路：

+   面包板（半尺寸或更大）

+   7 根 DuPont 母对公排线

+   六个按钮

+   6 个 470 欧姆电阻

+   面包板导线（实心线）

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/a4eac434-a135-49ff-bdb7-e4b98accf7ae.png)GPIO 键盘电路布局

键盘电路也可以通过将组件焊接到 Vero 原型板（也称为条板）中，制成永久电路，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/121e0320-e6c0-4ade-b143-64e253df5e16.png)GPIO 键盘 Pi 硬件模块这个电路可以从[PiHardware.com](http://pihardware.com/)购买成套焊接套件。

1.  通过将适当的按钮与适当的引脚相匹配，将电路连接到树莓派 GPIO 引脚，如下表所示：

|  | **按钮** | **GPIO 引脚** |
| --- | --- | --- |
| GND |  | 6 |
| v | B_DOWN | 22 |
| < | B_LEFT | 18 |
| ^ | B_UP | 15 |
| > | B_RIGHT | 13 |
| 1 | B_1 | 11 |
| 2 | B_2 | 7 |

# 如何做...

创建一个名为`gpiokeys.py`的脚本，如下所示：

```py
#!/usr/bin/python3 
#gpiokeys.py 
import time 
import RPi.GPIO as GPIO 
import uinput 

#HARDWARE SETUP 
# GPIO 
# 2[==G=====<=V==]26[=======]40 
# 1[===2=1>^=====]25[=======]39 
B_DOWN  = 22    #V 
B_LEFT  = 18   #< 
B_UP    = 15   #^ 
B_RIGHT = 13   #> 
B_1  = 11   #1 
B_2  = 7   #2 

DEBUG=True 
BTN = [B_UP,B_DOWN,B_LEFT,B_RIGHT,B_1,B_2] 
MSG = ["UP","DOWN","LEFT","RIGHT","1","2"] 

#Setup the DPad module pins and pull-ups 
def dpad_setup(): 
  #Set up the wiring 
  GPIO.setmode(GPIO.BOARD) 
  # Setup BTN Ports as INPUTS 
  for val in BTN: 
    # set up GPIO input with pull-up control 
    #(pull_up_down can be: 
    #    PUD_OFF, PUD_UP or PUD_DOWN, default PUD_OFF) 
    GPIO.setup(val, GPIO.IN, pull_up_down=GPIO.PUD_UP) 

def main(): 
  #Setup uinput 
  events = (uinput.KEY_UP,uinput.KEY_DOWN,uinput.KEY_LEFT, 
           uinput.KEY_RIGHT,uinput.KEY_ENTER,uinput.KEY_ENTER) 
  device = uinput.Device(events) 
  time.sleep(2) # seconds 
  dpad_setup() 
  print("DPad Ready!") 

  btn_state=[False,False,False,False,False,False] 
  key_state=[False,False,False,False,False,False] 
  while True: 
    #Catch all the buttons pressed before pressing the related keys 
    for idx, val in enumerate(BTN): 
      if GPIO.input(val) == False: 
        btn_state[idx]=True 
      else: 
        btn_state[idx]=False 

    #Perform the button presses/releases (but only change state once) 
    for idx, val in enumerate(btn_state): 
      if val == True and key_state[idx] == False: 
        if DEBUG:print (str(val) + ":" + MSG[idx]) 
        device.emit(events[idx], 1) # Press. 
        key_state[idx]=True 
      elif val == False and key_state[idx] == True: 
        if DEBUG:print (str(val) + ":!" + MSG[idx]) 
        device.emit(events[idx], 0) # Release. 
        key_state[idx]=False 

    time.sleep(.1) 

try: 
  main() 
finally: 
  GPIO.cleanup() 
#End 
```

# 它是如何工作的...

首先，我们导入`uinput`并定义键盘按钮的接线。对于`BTN`中的每个按钮，我们将它们启用为输入，并启用内部上拉。

接下来，我们设置`uinput`，定义我们想要模拟的键，并将它们添加到`uinput.Device()`函数中。我们等待几秒钟，以便`uinput`初始化，设置初始按钮和键状态，并启动我们的`main`循环。

`main`循环分为两个部分：第一部分检查按钮并记录`btn_state`中的状态，第二部分将`btn_state`与当前的`key_state`数组进行比较。这样，我们可以检测到`btn_state`的变化，并调用`device.emit()`来切换键的状态。

为了让我们能够在后台运行此脚本，我们可以使用`&`运行它，如下所示

以下命令：

```py
sudo python3 gpiokeys.py &  
```

`&`字符允许命令在后台运行，因此我们可以继续使用命令行运行其他程序。您可以使用`fg`将其带回前台，或者如果有多个命令正在运行，则可以使用`%1`，`%2`等。使用`jobs`获取列表。

您甚至可以通过按下*Ctrl* + *Z*将进程/程序暂停以进入命令提示符，然后使用`bg`恢复它（这将使其在后台运行）。

# 更多信息...

我们可以使用`uinput`来为其他程序提供硬件控制，包括那些需要鼠标输入的程序。

# 生成其他按键组合

您可以在文件中创建几种不同的键映射以支持不同的程序。例如，`events_z80`键映射对于像**Fuse**这样的光谱模拟器非常有用（浏览[`raspi.tv/2012/how-to-install-fuse-zx-spectrum-emulator-on-raspberry-pi`](http://raspi.tv/2012/how-to-install-fuse-zx-spectrum-emulator-on-raspberry-pi)获取更多详细信息）。`events_omx`键映射适用于使用以下命令控制通过 OMXPlayer 播放的视频：

```py
omxplayer filename.mp4  
```

您可以使用`-k`参数获取`omxplayer`支持的键列表。

用新的键映射替换定义`events`列表的行，并通过以下代码将它们分配给事件来选择不同的键：

```py
events_dpad = (uinput.KEY_UP,uinput.KEY_DOWN,uinput.KEY_LEFT, 
              uinput.KEY_RIGHT,uinput.KEY_ENTER,uinput.KEY_ENTER) 
events_z80 = (uinput.KEY_Q,uinput.KEY_A,uinput.KEY_O, 
             uinput.KEY_P,uinput.KEY_M,uinput.KEY_ENTER) 
events_omx = (uinput.KEY_EQUAL,uinput.KEY_MINUS,uinput.KEY_LEFT, 
             uinput.KEY_RIGHT,uinput.KEY_P,uinput.KEY_Q) 
```

您可以在`input.h`文件中找到所有的`KEY`定义；您可以使用`less`命令查看它（按*Q*退出），如下所示：

```py
less /usr/include/linux/input.h  
```

# 模拟鼠标事件

`uinput`库可以模拟鼠标和操纵杆事件，以及键盘按键。要使用按钮模拟鼠标，我们可以调整脚本以使用鼠标事件（以及定义`mousemove`来设置移动的步长），使用以下代码：

```py
MSG = ["M_UP","M_DOWN","M_LEFT","M_RIGHT","1","Enter"] 
events_mouse=(uinput.REL_Y,uinput.REL_Y, uinput.REL_X, 
             uinput.REL_X,uinput.BTN_LEFT,uinput.BTN_RIGHT) 
mousemove=1 
```

我们还需要修改按钮处理以提供连续移动，因为我们不需要跟踪鼠标键的状态。为此，请使用以下代码：

```py
#Perform the button presses/releases 
#(but only change state once) 
for idx, val in enumerate(btn_state): 
  if MSG[idx] == "M_UP" or MSG[idx] == "M_LEFT": 
    state = -mousemove 
  else: 
    state = mousemove 
  if val == True: 
    device.emit(events[idx], state) # Press. 
  elif val == False: 
    device.emit(events[idx], 0) # Release. 
time.sleep(0.01) 
```

# 多路复用的彩色 LED

本章的下一个示例演示了一些看似简单的硬件如果通过软件控制可以产生一些令人印象深刻的结果。为此，我们将回到使用 RGB LED。我们将使用五个 RGB LED，这些 LED 被布线，以便我们只需要使用八个 GPIO 引脚来控制它们的红色、绿色和蓝色元素，使用一种称为**硬件多路复用**的方法（请参阅本食谱的*硬件多路复用*子部分中的*更多信息*部分）。

# 准备工作

您将需要以下图片中显示的 RGB LED 模块：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/f240314f-3d20-4e18-839d-b4bea49a7025.png)PiHardware.com 的 RGB LED 模块

正如您在上面的照片中所看到的，来自[`pihardware.com/`](http://pihardware.com/)的 RGB LED 模块带有 GPIO 引脚和杜邦母对母电缆用于连接。虽然有两组从 1 到 5 标记的引脚，但只需要连接一侧。

或者，您可以使用五个共阳极 RGB LED、3 个 470 欧姆电阻和一个 Vero 原型板（或大型面包板）来重新创建自己的电路。电路将如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/2e014247-64dd-4885-a536-b51c3b1454b0.png)RGB LED 模块的电路图严格来说，我们应该在这个电路中使用 15 个电阻（每个 RGB LED 元件一个），这样可以避免 LED 共用同一个电阻的干扰，并且在一起开启时也会延长 LED 的寿命。然而，使用这种方法只有轻微的优势，特别是因为我们打算独立驱动每个 RGB LED，以实现多种颜色效果。

您需要将电路连接到树莓派 GPIO 引脚头，连接方式如下：

| **RGB LED** |  |  |  |  |  | 1 |  | 2 | 3 |  | 4 |  |  |  |  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Rpi GPIO 引脚** | 2 | 4 | 6 | 8 | 10 | 12 | 14 | 16 | 18 | 20 | 22 | 24 | 26 | 28 | 30 | 32 | 34 | 36 | 38 | 40 |
| **Rpi GPIO 引脚** | 1 | 3 | 5 | 7 | 9 | 11 | 13 | 15 | 17 | 19 | 21 | 23 | 25 | 27 | 29 | 31 | 33 | 35 | 37 | 39 |
| **RGB LED** |  |  |  | 5 |  | R | G | B |  |  |  |  |  |  |  |  |  |  |  |  |

# 如何做到这一点...

创建`rgbled.py`脚本，并执行以下步骤：

1.  导入所有所需的模块，并使用以下代码定义要使用的值： 

```py
#!/usr/bin/python3 
#rgbled.py 
import time 
import RPi.GPIO as GPIO 

#Setup Active states 
#Common Cathode RGB-LEDs (Cathode=Active Low) 
LED_ENABLE = 0; LED_DISABLE = 1 
RGB_ENABLE = 1; RGB_DISABLE = 0 
#HARDWARE SETUP 
# GPIO 
# 2[=====1=23=4==]26[=======]40 
# 1[===5=RGB=====]25[=======]39 
#LED CONFIG - Set GPIO Ports 
LED1 = 12; LED2 = 16; LED3 = 18; LED4 = 22; LED5 = 7 
LED = [LED1,LED2,LED3,LED4,LED5] 
RGB_RED = 11; RGB_GREEN = 13; RGB_BLUE = 15 
RGB = [RGB_RED,RGB_GREEN,RGB_BLUE] 
#Mixed Colors 
RGB_CYAN = [RGB_GREEN,RGB_BLUE] 
RGB_MAGENTA = [RGB_RED,RGB_BLUE] 
RGB_YELLOW = [RGB_RED,RGB_GREEN] 
RGB_WHITE = [RGB_RED,RGB_GREEN,RGB_BLUE] 
RGB_LIST = [RGB_RED,RGB_GREEN,RGB_BLUE,RGB_CYAN, 
            RGB_MAGENTA,RGB_YELLOW,RGB_WHITE] 
```

1.  定义使用以下代码设置 GPIO 引脚的函数：

```py
def led_setup(): 
  '''Setup the RGB-LED module pins and state.''' 
  #Set up the wiring 
  GPIO.setmode(GPIO.BOARD) 
  # Setup Ports 
  for val in LED: 
    GPIO.setup(val, GPIO.OUT) 
  for val in RGB: 
    GPIO.setup(val, GPIO.OUT) 
  led_clear()
```

1.  使用以下代码定义我们的实用程序函数来帮助控制 LED：

```py
def led_gpiocontrol(pins,state): 
  '''This function will control the state of 
  a single or multiple pins in a list.''' 
  #determine if "pins" is a single integer or not 
  if isinstance(pins,int): 
    #Single integer - reference directly 
    GPIO.output(pins,state) 
  else: 
    #if not, then cycle through the "pins" list 
    for i in pins: 
      GPIO.output(i,state) 

def led_activate(led,color): 
  '''Enable the selected led(s) and set the required color(s) 
  Will accept single or multiple values''' 
  #Enable led 
  led_gpiocontrol(led,LED_ENABLE) 
  #Enable color 
  led_gpiocontrol(color,RGB_ENABLE) 

def led_deactivate(led,color): 
  '''Deactivate the selected led(s) and set the required 
  color(s) will accept single or multiple values''' 
  #Disable led 
  led_gpiocontrol(led,LED_DISABLE) 
  #Disable color 
  led_gpiocontrol(color,RGB_DISABLE) 

def led_time(led, color, timeon): 
  '''Switch on the led and color for the timeon period''' 
  led_activate(led,color) 
  time.sleep(timeon) 
  led_deactivate(led,color) 

def led_clear(): 
  '''Set the pins to default state.''' 
  for val in LED: 
    GPIO.output(val, LED_DISABLE) 
  for val in RGB: 
    GPIO.output(val, RGB_DISABLE) 

def led_cleanup(): 
  '''Reset pins to default state and release GPIO''' 
  led_clear() 
  GPIO.cleanup()
```

1.  创建一个测试函数来演示模块的功能：

```py
def main(): 
  '''Directly run test function. 
  This function will run if the file is executed directly''' 
  led_setup() 
  led_time(LED1,RGB_RED,5) 
  led_time(LED2,RGB_GREEN,5) 
  led_time(LED3,RGB_BLUE,5) 
  led_time(LED,RGB_MAGENTA,2) 
  led_time(LED,RGB_YELLOW,2) 
  led_time(LED,RGB_CYAN,2)  

if __name__=='__main__': 
  try: 
    main() 
  finally: 
    led_cleanup() 
#End 
```

# 它是如何工作的...

首先，我们通过定义所需的状态来定义硬件设置，以便根据使用的 RGB LED（共阳极）的类型来**启用**和**禁用**LED。如果您使用的是共阳极设备，只需颠倒**启用**和**禁用**状态。

接下来，我们定义 GPIO 映射到引脚，以匹配我们之前进行的接线。

我们还通过组合红色、绿色和/或蓝色来定义一些基本的颜色组合，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/7e1997f5-945b-402a-8cfe-8be0de9ea29d.png)LED 颜色组合

我们定义了一系列有用的函数，首先是`led_setup()`，它将把 GPIO 编号设置为`GPIO.BOARD`，并定义所有要用作输出的引脚。我们还调用一个名为`led_clear()`的函数，它将把引脚设置为默认状态，所有引脚都被禁用。

这意味着 LED 引脚 1-5（每个 LED 的共阳极）被设置为`HIGH`，而 RGB 引脚（每种颜色的单独阳极）被设置为`LOW`。

我们创建一个名为`led_gpiocontrol()`的函数，它将允许我们设置一个或多个引脚的状态。`isinstance()`函数允许我们测试一个值，看它是否匹配特定类型（在本例中是单个整数）；然后我们可以设置单个引脚的状态，或者遍历引脚列表并设置每个引脚的状态。

接下来，我们定义两个函数，`led_activate()`和`led_deactivate()`，它们将启用和禁用指定的 LED 和颜色。最后，我们定义`led_time()`，它将允许我们指定 LED、颜色和开启时间。

我们还创建`led_cleanup()`来将引脚（和 LED）重置为默认值，并调用`GPIO.cleanup()`来释放正在使用的 GPIO 引脚。

这个脚本旨在成为一个库文件，因此我们将使用`if __name__=='__main__'`检查，只有在直接运行文件时才运行我们的测试代码：

通过检查`__name__`的值，我们可以确定文件是直接运行的（它将等于`__main__`），还是被另一个 Python 脚本导入的。

这使我们能够定义一个特殊的测试代码，只有在直接加载和运行文件时才执行。如果我们将此文件作为另一个脚本中的模块包含，那么此代码将不会被执行。

与以前一样，我们将使用`try`/`finally`来允许我们始终执行清理操作，即使我们提前退出。

为了测试脚本，我们将设置 LED 依次以各种颜色点亮。

# 还有更多...

我们可以通过一次打开 RGB LED 的一个或多个部分来创建几种不同的颜色。然而，通过一些巧妙的编程，我们可以创建整个颜色谱。此外，我们可以似乎同时在每个 LED 上显示不同的颜色。

# 硬件复用

LED 需要在阳极侧施加高电压，在阴极侧施加低电压才能点亮。电路中使用的 RGB LED 是共阳极的，因此我们必须在 RGB 引脚上施加高电压（3V3），在阴极引脚上施加低电压（0V）（分别连接到每个 LED 的 1 到 5 引脚）。

阴极和 RGB 引脚状态如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/c3aaca65-07d4-4d44-b773-91f3cb7f242f.png)阴极和 RGB 引脚状态

因此，我们可以启用一个或多个 RGB 引脚，但仍然控制点亮哪个 LED。我们启用我们想要点亮的 LED 的引脚，并禁用我们不想点亮的引脚。这使我们可以使用比控制每个 RGB 线需要的引脚少得多的引脚。

# 显示随机图案

我们可以向我们的库中添加新的函数以产生不同的效果，例如生成随机颜色。以下函数使用`randint()`来获取 1 到颜色数量之间的值。我们忽略任何超出可用颜色数量的值，以便我们可以控制 LED 关闭的频率。执行以下步骤以添加所需的函数：

1.  使用以下代码将`random`模块中的`randint()`函数添加到`rgbled.py`脚本中：

```py
from random import randint
```

1.  现在使用以下代码添加`led_rgbrandom()`：

```py
def led_rgbrandom(led,period,colors): 
   ''' Light up the selected led, for period in seconds, 
   in one of the possible colors. The colors can be 
   1 to 3 for RGB, or 1-6 for RGB plus combinations, 
   1-7 includes white. Anything over 7 will be set as 
   OFF (larger the number more chance of OFF).'''  
  value = randint(1,colors) 
  if value < len(RGB_LIST): 
    led_time(led,RGB_LIST[value-1],period) 
```

1.  在`main()`函数中使用以下命令创建一系列

闪烁 LED：

```py
for i in range(20): 
  for j in LED: 
    #Select from all, plus OFF 
    led_rgbrandom(j,0.1,20) 
```

# 混合多种颜色

到目前为止，我们只在一个或多个 LED 上一次显示一种颜色。如果考虑电路的接线方式，您可能会想知道我们如何让一个 LED 同时显示一种颜色，而另一个显示不同的颜色。简单的答案是我们不需要-我们只是快速地做到这一点！

我们所需要做的就是一次显示一种颜色，但来回变换，变换得如此之快，以至于颜色看起来像两种颜色的混合（甚至是三种红/绿/蓝 LED 的组合）。幸运的是，树莓派等计算机可以很容易地做到这一点，甚至允许我们组合 RGB 元素以在所有五个 LED 上制作多种颜色。执行以下步骤来混合颜色：

1.  在`rgbled.py`脚本的顶部添加组合颜色定义，在混合颜色的定义之后，使用以下代码：

```py
#Combo Colors 
RGB_AQUA = [RGB_CYAN,RGB_GREEN] 
RGB_LBLUE = [RGB_CYAN,RGB_BLUE] 
RGB_PINK = [RGB_MAGENTA,RGB_RED] 
RGB_PURPLE = [RGB_MAGENTA,RGB_BLUE] 
RGB_ORANGE = [RGB_YELLOW,RGB_RED] 
RGB_LIME = [RGB_YELLOW,RGB_GREEN] 
RGB_COLORS = [RGB_LIME,RGB_YELLOW,RGB_ORANGE,RGB_RED, 
              RGB_PINK,RGB_MAGENTA,RGB_PURPLE,RGB_BLUE, 
              RGB_LBLUE,RGB_CYAN,RGB_AQUA,RGB_GREEN] 
```

上述代码将提供创建我们所需的颜色组合，`RGB_COLORS`提供了对颜色的平滑过渡。

1.  接下来，我们需要创建一个名为`led_combo()`的函数来处理单个或多个颜色。该函数的代码如下：

```py
def led_combo(pins,colors,period): 
  #determine if "colors" is a single integer or not 
  if isinstance(colors,int): 
    #Single integer - reference directly 
    led_time(pins,colors,period) 
  else: 
    #if not, then cycle through the "colors" list 
    for i in colors: 
      led_time(pins,i,period) 
```

1.  现在我们可以创建一个新的脚本`rgbledrainbow.py`，以利用我们`rgbled.py`模块中的新功能。`rgbledrainbow.py`脚本将如下所示：

```py
#!/usr/bin/python3 
#rgbledrainbow.py 
import time 
import rgbled as RGBLED 

def next_value(number,max): 
  number = number % max 
  return number 

def main(): 
  print ("Setup the RGB module") 
  RGBLED.led_setup() 

  # Multiple LEDs with different Colors 
  print ("Switch on Rainbow") 
  led_num = 0 
  col_num = 0 
  for l in range(5): 
    print ("Cycle LEDs") 
    for k in range(100): 
      #Set the starting point for the next set of colors 
      col_num = next_value(col_num+1,len(RGBLED.RGB_COLORS)) 
      for i in range(20):  #cycle time 
        for j in range(5): #led cycle 
          led_num = next_value(j,len(RGBLED.LED)) 
          led_color = next_value(col_num+led_num, 
                                 len(RGBLED.RGB_COLORS)) 
          RGBLED.led_combo(RGBLED.LED[led_num], 
                           RGBLED.RGB_COLORS[led_color],0.001) 

    print ("Cycle COLORs")         
    for k in range(100): 
      #Set the next color 
      col_num = next_value(col_num+1,len(RGBLED.RGB_COLORS)) 
      for i in range(20): #cycle time 
        for j in range(5): #led cycle 
          led_num = next_value(j,len(RGBLED.LED)) 
          RGBLED.led_combo(RGBLED.LED[led_num], 
                           RGBLED.RGB_COLORS[col_num],0.001) 
  print ("Finished") 

if __name__=='__main__': 
  try: 
    main() 
  finally: 
    RGBLED.led_cleanup() 
#End 
```

`main()`函数将首先循环遍历 LED，将`RGB_COLORS`数组中的每种颜色设置在所有 LED 上。然后，它将循环遍历颜色，在 LED 上创建彩虹效果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/2709e07f-71c2-43ff-b175-3bc84d4e4c45.png)在五个 RGB LED 上循环显示多种颜色

# 使用视觉持久性编写消息

**视觉持续性**（**POV**）显示可以产生一种几乎神奇的效果，通过快速来回移动一行 LED 或在圆圈中移动 LED 来在空中显示图像。这种效果的原理是因为您的眼睛无法调整得足够快，以分离出单独的闪光，因此您观察到一个合并的图像（显示的消息或图片）：

！[](Images/221d8d87-7773-4f9b-91eb-d4d610adade4.png)使用 RGB LED 的视觉持续性

# 准备工作

这个配方使用了前一个配方中使用的 RGB LED 套件；您还需要以下额外的物品：

+   面包板（半尺寸或更大）

+   2 x DuPont 母对公跳线

+   倾斜开关（适合滚珠类型）

+   1 x 470 欧姆电阻（R_Protect）

+   面包板线（实心线）

倾斜开关应添加到 RGB LED（如*准备工作*部分的*多路复用彩色 LED*配方中所述）。倾斜开关的接线如下：

！[](Images/60548e93-3f4c-411f-9f5a-76df3d0b07d4.png)倾斜开关连接到 GPIO 输入（GPIO 引脚 24）和 Gnd（GPIO 引脚 6）

为了重现 POV 图像，您需要能够快速移动 LED 并来回倾斜开关。请注意倾斜开关安装在侧面倾斜，因此当向左移动时开关将打开。建议将硬件安装在一根木头或类似设备上。您甚至可以使用便携式 USB 电池组和 Wi-Fi dongle 来通过远程连接为树莓派供电和控制（有关详细信息，请参见*第一章*中的*通过网络远程连接树莓派使用 SSH（和 X11 转发）*配方）：

！[](Images/dd5c1ecb-a851-40a1-b565-38d5f70b6666.png)持续视觉硬件设置

您还需要已完成的`rgbled.py`文件，我们将在*如何操作*...部分进一步扩展它。

# 如何操作...

1.  创建一个名为`tilt.py`的脚本来报告倾斜开关的状态：

```py
#!/usr/bin/python3 
#tilt.py 
import RPi.GPIO as GPIO 
#HARDWARE SETUP 
# GPIO 
# 2[===========T=]26[=======]40 
# 1[=============]25[=======]39 
#Tilt Config 
TILT_SW = 24 

def tilt_setup(): 
  #Setup the wiring 
  GPIO.setmode(GPIO.BOARD) 
  #Setup Ports 
  GPIO.setup(TILT_SW,GPIO.IN,pull_up_down=GPIO.PUD_UP) 

def tilt_moving(): 
  #Report the state of the Tilt Switch 
  return GPIO.input(TILT_SW) 

def main(): 
  import time 
  tilt_setup() 
  while True: 
    print("TILT %s"% (GPIO.input(TILT_SW))) 
    time.sleep(0.1) 

if __name__=='__main__': 
  try: 
    main() 
  finally: 
    GPIO.cleanup() 
    print("Closed Everything. END") 
#End 
```

1.  您可以通过直接运行以下命令来测试脚本：

```py
sudo python3 tilt.py
```

1.  将以下`rgbled_pov()`函数添加到我们之前创建的`rgbled.py`脚本中；这将允许我们显示图像的单行：

```py
def rgbled_pov(led_pattern,color,ontime): 
  '''Disable all the LEDs and re-enable the LED pattern in the required color''' 
  led_deactivate(LED,RGB) 
  for led_num,col_num in enumerate(led_pattern): 
    if col_num >= 1: 
      led_activate(LED[led_num],color) 
  time.sleep(ontime) 
```

1.  现在，我们将创建以下文件，名为`rgbledmessage.py`，以执行显示我们的消息所需的操作。首先，我们将导入所使用的模块：更新的`rgbled`模块，新的`tilt`模块和 Python `os`模块。最初，我们将`DEBUG`设置为`True`，这样 Python 终端在脚本运行时将显示额外的信息：

```py
#!/usr/bin/python3 
# rgbledmessage.py 
import rgbled as RGBLED 
import tilt as TILT 
import os 

DEBUG = True 
```

1.  添加一个`readMessageFile()`函数来读取`letters.txt`文件的内容，然后添加`processFileContent()`来为每个字母生成一个 LED 模式的**Python 字典**：

```py
def readMessageFile(filename): 
  assert os.path.exists(filename), 'Cannot find the message file: %s' % (filename) 
  try: 
    with open(filename, 'r') as theFile: 
    fileContent = theFile.readlines() 
  except IOError: 
    print("Unable to open %s" % (filename)) 
  if DEBUG:print ("File Content START:") 
  if DEBUG:print (fileContent) 
  if DEBUG:print ("File Content END") 
  dictionary = processFileContent(fileContent) 
  return dictionary  

def processFileContent(content): 
  letterIndex = [] #Will contain a list of letters stored in the file 
  letterList = []  #Will contain a list of letter formats 
  letterFormat = [] #Will contain the format of each letter 
  firstLetter = True 
  nextLetter = False 
  LETTERDIC={} 
  #Process each line that was in the file 
  for line in content: 
    # Ignore the # as comments 
    if '#' in line: 
      if DEBUG:print ("Comment: %s"%line) 
    #Check for " in the line = index name   
    elif '"' in line: 
      nextLetter = True 
      line = line.replace('"','') #Remove " characters 
      LETTER=line.rstrip() 
      if DEBUG:print ("Index: %s"%line) 
    #Remaining lines are formatting codes 
    else: 
      #Skip firstLetter until complete 
      if firstLetter: 
        firstLetter = False 
        nextLetter = False 
        lastLetter = LETTER 
      #Move to next letter if needed 
      if nextLetter: 
        nextLetter = False 
        LETTERDIC[lastLetter]=letterFormat[:] 
        letterFormat[:] = [] 
        lastLetter = LETTER 
      #Save the format data 
      values = line.rstrip().split(' ') 
      row = [] 
      for val in values: 
        row.append(int(val)) 
      letterFormat.append(row) 
  LETTERDIC[lastLetter]=letterFormat[:] 
  #Show letter patterns for debugging 
  if DEBUG:print ("LETTERDIC: %s" %LETTERDIC) 
  if DEBUG:print ("C: %s"%LETTERDIC['C']) 
  if DEBUG:print ("O: %s"%LETTERDIC['O']) 
  return LETTERDIC
```

1.  添加一个`createBuffer()`函数，它将把消息转换为每个字母的 LED 模式系列（假设该字母由`letters.txt`文件定义）：

```py
def createBuffer(message,dictionary): 
  buffer=[] 
  for letter in message: 
    try: 
      letterPattern=dictionary[letter] 
    except KeyError: 
      if DEBUG:print("Unknown letter %s: use _"%letter) 
      letterPattern=dictionary['_'] 
    buffer=addLetter(letterPattern,buffer) 
  if DEBUG:print("Buffer: %s"%buffer) 
  return buffer 

def addLetter(letter,buffer): 
  for row in letter: 
    buffer.append(row) 
  buffer.append([0,0,0,0,0]) 
  buffer.append([0,0,0,0,0]) 
  return buffer 
```

1.  接下来，我们定义一个`displayBuffer()`函数，使用`rgbled`模块中的`rgbled_pov()`函数来显示 LED 模式：

```py
def displayBuffer(buffer): 
  position=0 
  while(1): 
    if(TILT.tilt_moving()==False): 
      position=0 
    elif (position+1)<len(buffer): 
      position+=1 
      if DEBUG:print("Pos:%s ROW:%s"%(position,buffer[position])) 
    RGBLED.rgbled_pov(buffer[position],RGBLED.RGB_GREEN,0.001) 
    RGBLED.rgbled_pov(buffer[position],RGBLED.RGB_BLUE,0.001) 
```

1.  最后，我们创建一个`main()`函数来执行所需的每个步骤：

1.  设置硬件组件（RGB LED 和倾斜开关）。

1.  阅读`letters.txt`文件。

1.  定义 LED 字母模式的字典。

1.  生成一个缓冲区来表示所需的消息。

1.  使用`rgbled`模块显示缓冲区，并使用`tilt`模块进行控制：

```py
def main(): 
  RGBLED.led_setup() 
  TILT.tilt_setup() 
  dict=readMessageFile('letters.txt') 
  buffer=createBuffer('_COOKBOOK_',dict) 
  displayBuffer(buffer) 

if __name__=='__main__': 
  try: 
    main() 
  finally: 
    RGBLED.led_cleanup() 
    print("Closed Everything. END") 
#End 
```

1.  创建以下文件，名为`letters.txt`，以定义显示示例`'_COOKBOOK_'`消息所需的 LED 模式。请注意，此文件只需要为消息中的每个唯一字母或符号定义一个模式：

```py
#COOKBOOK 
"C" 
0 1 1 1 0 
1 0 0 0 1 
1 0 0 0 1 
"O" 
0 1 1 1 0 
1 0 0 0 1 
1 0 0 0 1 
0 1 1 1 0 
"K" 
1 1 1 1 1 
0 1 0 1 0 
1 0 0 0 1 
"B" 
1 1 1 1 1 
1 0 1 0 1 
0 1 0 1 0 
"_" 
0 0 0 0 0 
0 0 0 0 0 
0 0 0 0 0 
0 0 0 0 0 
0 0 0 0 0 
```

# 工作原理...

第一个函数“readMessageFile（）”将打开并读取给定文件的内容。然后使用“processFileContent（）”返回一个包含文件中定义的字母对应的 LED 图案的 Python 字典。处理文件时，会处理文件中的每一行，忽略包含“＃”字符的任何行，并检查“”字符以指示接下来的 LED 图案的名称。处理文件后，我们得到一个包含 LED 图案的 Python 字典，其中包含`'_'`、`'C'`、`'B'`、`'K'`和`'O'`字符。

```py
'_': [[0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0]] 
'C': [[0, 1, 1, 1, 0], [1, 0, 0, 0, 1], [1, 0, 0, 0, 1]] 
'B': [[1, 1, 1, 1, 1], [1, 0, 1, 0, 1], [0, 1, 0, 1, 0]] 
'K': [[1, 1, 1, 1, 1], [0, 1, 0, 1, 0], [1, 0, 0, 0, 1]] 
'O': [[0, 1, 1, 1, 0], [1, 0, 0, 0, 1], [1, 0, 0, 0, 1], [0, 1, 1, 1, 0]] 
```

现在我们有一系列可供选择的字母，我们可以使用“createBuffer（）”函数创建 LED 图案序列。正如其名称所示，该函数将通过查找消息中的每个字母并逐行添加相关的图案来构建 LED 图案的缓冲区。如果在字典中找不到字母，则将使用空格代替。

最后，我们现在有一系列准备显示的 LED 图案。为了控制我们何时开始序列，我们将使用 TILT 模块并检查倾斜开关的状态：

当倾斜开关不移动时的位置（左）和移动时的位置（右）

倾斜开关由一个小滚珠封闭在一个空心绝缘圆柱体中组成；当球静止在圆柱体底部时，两个引脚之间的连接闭合。当球移动到圆柱体的另一端，远离引脚的接触时，倾斜开关打开：

倾斜开关电路，开关闭合和开关打开时

先前显示的倾斜开关电路将在开关闭合时将 GPIO 引脚 24 连接到地。然后，如果我们读取引脚，当它静止时将返回`False`。通过将 GPIO 引脚设置为输入并启用内部上拉电阻，当倾斜开关打开时，它将报告`True`。

如果倾斜开关是打开的（报告`True`），那么我们将假设单位正在移动，并开始显示 LED 序列，每次显示 LED 图案的一行时递增当前位置。为了使图案更加丰富多彩（只是因为我们可以！），我们会用另一种颜色重复每一行。一旦“TILT.tilt_moving（）”函数报告我们已经停止移动或者我们正在向相反方向移动，我们将重置当前位置，准备重新开始整个图案：

消息由 RGB LED 显示 - 在这里，我们一起使用绿色和蓝色

当 RGB LED 模块和倾斜开关来回移动时，我们应该看到消息在空中显示！

尝试尝试不同的颜色组合、速度和手臂挥动，看看你能产生什么效果。你甚至可以创建一个类似的设置，安装在车轮上，产生连续的 POV 效果。


# 第八章：感知和显示真实世界的数据

在本章中，我们将涵盖以下主题：

+   使用 I2C 总线的设备

+   使用模拟数字转换器读取模拟数据

+   记录和绘制数据

+   通过 I/O 扩展器扩展树莓派 GPIO

+   在 SQLite 数据库中捕获数据

+   查看来自您自己的 Web 服务器的数据

+   感知和发送数据到在线服务

# 介绍

在本章中，我们将学习如何收集来自现实世界的模拟数据并对其进行处理，以便在程序中显示、记录、绘制和共享数据，并利用这些数据。

我们将通过使用树莓派的 GPIO 连接来扩展树莓派的功能，与模拟数字转换器（ADC）、LCD 字母显示器和数字端口扩展器进行接口。

# 使用 I2C 总线的设备

树莓派可以支持多种高级协议，可以轻松连接各种设备。在本章中，我们将专注于最常见的总线，称为 I-squared-C（I²C）。它提供了一个用于通过两根导线与设备通信的中速总线。在本节中，我们将使用 I²C 与 8 位 ADC 进行接口。该设备将测量模拟信号，将其转换为 0 到 255 之间的相对值，并将该值作为数字信号（由 8 位表示）通过 I²C 总线发送到树莓派。

I²C 的优势可以总结如下：

+   即使在总线上有许多设备的情况下，也能保持低引脚/信号计数

+   适应不同从设备的需求

+   容易支持多个主设备

+   包括 ACK/NACK 功能以改进错误处理

# 准备工作

并非所有树莓派镜像都启用了 I²C 总线；因此，我们需要启用模块并安装一些支持工具。Raspbian 的新版本使用设备树来处理硬件外围设备和驱动程序。

为了使用 I²C 总线，我们需要在`bootconfig.txt`文件中启用 ARM I²C。

您可以使用以下命令自动执行此操作：

```py
sudo raspi-config
```

从菜单中选择高级选项，然后选择 I²C，如下截图所示。当询问时，选择是以启用接口，然后点击是以默认加载模块：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/de619297-5684-41b7-8733-887b49dc9185.png)raspi-config 菜单

从菜单中选择 I2C，选择是以启用接口并默认加载模块。

`raspi-config`程序通过修改`/boot/config.txt`以包括`dtparam=i2c_arm=on`来启用`I2C_ARM`接口。另一种总线（I2C_VC）通常保留用于与树莓派 HAT 附加板进行接口（从板载存储器设备读取配置信息）；但是，您也可以使用`dtparam=i2c_vc=on`来启用此功能。

如果您愿意，您还可以使用`raspi-config`列表启用 SPI，这是另一种类型的总线。

接下来，我们应该包括 I²C 模块在打开树莓派时加载，如下所示：

```py
sudo nano /etc/modules  
```

添加以下内容并保存（*Ctrl* + *X*, *Y*, *Enter*）：

```py
i2c-dev
i2c-bcm2708  
```

类似地，我们还可以通过添加`spi-bcm2708`来启用 SPI 模块。

接下来，我们将安装一些工具，以便直接从命令行使用 I²C 设备，如下所示：

```py
sudo apt-get update
sudo apt-get install i2c-tools  
```

最后，在连接硬件之前关闭树莓派，以便应用更改，如下所示：

```py
sudo halt  
```

您将需要一个 PCF8591 模块（这些的零售商在附录*硬件和软件清单*中列出）或者您可以单独获取 PCF8591 芯片并构建自己的电路（有关电路的详细信息，请参阅*还有更多...*部分）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/41781e79-5740-4a5f-a202-14e498aae716.png)来自 dx.com 的 PCF8591 ADC 和传感器模块

将 GND、VCC、SDA 和 SCL 引脚连接到树莓派的 GPIO 引脚头，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/e4093aac-4d52-4588-8bbf-7e2bb556d812.png)树莓派 GPIO 引脚上的 I2C 连接您可以通过研究设备的数据表找出要发送/读取的消息以及用于控制设备的寄存器，使用相同的 I²C 工具/代码与其他 I²C 设备。

# 操作步骤...

1.  `i2cdetect`命令用于检测 I²C 设备（`--y`选项跳过有关可能干扰连接到 I²C 总线的其他硬件的警告）。以下命令用于扫描两个总线：

```py
sudo i2cdetect -y 0
sudo i2cdetect -y 1 
```

1.  根据您的树莓派板子版本，设备的地址应该在总线 0 上列出（适用于 Model B Rev1 板）或总线 1 上（适用于树莓派 2 和 3，以及树莓派 1 Model A 和 Model B Revision 2）。默认情况下，PCF8591 地址是`0x48`：

| **要使用的 I²C 总线号** | **总线 00** | **总线 11** |
| --- | --- | --- |
| 树莓派 2 和 3 | HAT ID（I2C_VC） | GPIO（I2C_ARM） |
| Model A 和 Model B Revision 2 | P5 | GPIO |
| Model B Revision 1 | GPIO | N/A |

1.  以下屏幕截图显示了`i2cdetect`的输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/987cdc05-6091-4931-be83-02cbe8e5871f.png)PCF8591 地址（48）在总线 1 上显示

如果没有列出任何内容，请关闭并仔细检查您的连接（来自[www.dx.com](http://www.dx.com/)的 ADC 模块在上电时会打开红色 LED）。

如果收到错误消息，指出`/dev/i2c1`总线不存在，您可以执行以下检查：

+   确保`/etc/modprobe.d/raspi-blacklist.conf`文件为空（即模块未被列入黑名单），使用以下命令查看文件：

`           sudo nano /etc/modprobe.d/raspi-blacklist.conf`

+   如果文件中有任何内容（例如`blacklist i2c-bcm2708`），请删除并保存

+   检查`/boot/config`，确保没有包含`device_tree_param=`的行（这将禁用对新设备树配置的支持，并禁用对某些树莓派 HAT 附加板的支持）

+   使用`lsmod`检查模块是否已加载，并查找`i2c-bcm2708`和`i2c_dev`

1.  使用检测到的总线号（`0`或`1`）和设备地址（`0x48`），使用`i2cget`从设备读取（上电或通道更改后，您需要两次读取设备才能看到最新值），如下所示：

```py
sudo i2cget -y 1 0x48
sudo i2cget -y 1 0x48 
```

1.  要从通道`1`读取（这是模块上的温度传感器），我们可以使用`i2cset`将`0x01`写入 PCF8591 控制寄存器。同样，使用两次读取来从通道`1`获取新样本，如下所示：

```py
sudo i2cset -y 1 0x48 0x01
sudo i2cget -y 1 0x48
sudo i2cget -y 1 0x48
```

1.  要循环遍历每个输入通道，请使用`i2cset`将控制寄存器设置为`0x04`，如下所示：

```py
sudo i2cset -y 1 0x48 0x04
```

1.  我们还可以使用以下命令控制 AOUT 引脚，将其完全打开（点亮 LED D1）：

```py
sudo i2cset -y 1 0x48 0x40 0xff 
```

1.  最后，我们可以使用以下命令将其完全关闭（关闭 LED D1）：

```py
sudo i2cset -y 1 0x48 0x40 0x00  
```

# 工作原理...

设备上电后的第一次读取将返回`0x80`，并且还将触发通道 0 的新样本。如果再次读取，它将返回先前读取的样本并生成新样本。每次读取都将是一个 8 位值（范围从`0`到`255`），表示电压到 VCC（在本例中为 0V 到 3.3V）。在[www.dx.com](http://www.dx.com)模块上，通道 0 连接到光传感器，因此如果用手遮住模块并重新发送命令，您将观察到值的变化（较暗表示较高的值，较亮表示较低的值）。您会发现读数总是滞后一步；这是因为当它返回先前的样本时，它捕获了下一个样本。

我们使用以下命令指定要读取的特定通道：

```py
sudo i2cset -y 1 0x48 0x01  
```

这将更改要读取的通道为通道 1（在模块上标有**AIN1**）。请记住，您需要执行两次读取，然后才能从新选择的通道看到数据。以下表格显示了通道和引脚名称，以及哪些跳线连接器启用/禁用了每个传感器：

| **通道** | **0** | **1** | **2** | **3** |
| --- | --- | --- | --- | --- |
| 引脚名称 | AIN0 | AIN1 | AIN2 | AIN3 |
| 传感器 | 光敏电阻 | 热敏电阻 | 外部引脚 | 电位器 |
| 跳线 | P5 | P4 |  | P6 |

接下来，我们通过设置控制寄存器的模拟输出使能标志（第 6 位）来控制 AOUT 引脚，并使用下一个值来设置模拟电压（0V-3.3V，0x00-0xFF），如下所示：

```py
sudo i2cset -y 1 0x48 0x40 0xff   
```

最后，可以将第 2 位（`0x04`）设置为自动递增，并循环通过输入通道，如下所示：

```py
sudo i2cset -y 1 0x48 0x04
```

每次运行`i2cget -y 1 0x48`，下一个通道将被选择，从 AIN0 开始，然后从 AIN1 到 AIN3 再返回到 AIN0。

要理解如何设置值中的特定位，有助于查看数字的二进制表示。8 位值`0x04`可以用二进制`b0000 0100`来表示（`0x`表示值以十六进制表示，b 表示二进制数）。

二进制数中的位从右到左进行计数，从 0 开始 - 即，MSB 7 6 5 4 3 2 1 0 LSB。

第 7 位被称为**最高有效位**（**MSB**），第 0 位被称为**最低有效位**（**LSB**）。因此，通过设置第 2 位，我们最终得到`b0000 0100`（即`0x04`）。

# 还有更多...

I²C 总线允许我们只使用少量线路轻松连接多个设备。PCF8591 芯片可用于将自己的传感器连接到模块或仅连接芯片。

# 使用多个 I2C 设备

I²C 总线上的所有命令都是针对特定的 I²C 设备的（许多设备可以选择将一些引脚设为高电平或低电平以选择附加地址，并允许多个设备存在于同一总线上）。每个设备必须具有唯一地址，以便一次只有一个设备会做出响应。PCF8591 的起始地址是`0x48`，通过三个地址引脚可选择附加地址为`0x4F`。这允许在同一总线上使用多达八个 PCF8591 设备。

如果决定使用位于 GPIO 引脚 27 和 28（或位于 Model A 和 Revision 2 Model B 设备的 P5 标头）的 I2C_VC 总线，则可能需要在 I²C 线和 3.3V 之间添加 1k8 欧姆的上拉电阻。这些电阻已经存在于 GPIO 连接器上的 I²C 总线上。但是，一些 I²C 模块，包括 PCF8591 模块，已经安装了自己的电阻，因此可以在没有额外电阻的情况下工作。

# I2C 总线和电平转换

I²C 总线由两根线组成，一根数据线（SDA）和一根时钟线（SCL）。两根线都通过上拉电阻被被动地拉到 VCC（在树莓派上，这是 3.3V）。树莓派将通过每个周期将时钟线拉低来控制时钟，数据线可以被树莓派拉低以发送命令，或者被连接的设备拉低以回应数据：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/11df565b-2693-41b3-a66f-6bd9b04650f1.png)树莓派 I²C 引脚包括 SDA 和 SCL 上的上拉电阻

由于从机设备只能将数据线拉到**GND**，因此设备可以由 3.3V 甚至 5V 供电，而不会有驱动 GPIO 引脚电压过高的风险（请记住，树莓派 GPIO 无法处理超过 3.3V 的电压）。只要设备的 I²C 总线能够识别逻辑最大值为 3.3V 而不是 5V，这应该可以工作。I²C 设备不能安装自己的上拉电阻，因为这会导致 GPIO 引脚被拉到 I²C 设备的供电电压。

请注意，本章中使用的 PCF8591 模块已安装了电阻；因此，我们只能使用**VCC = 3V3**。双向逻辑电平转换器可用于克服逻辑电平的任何问题。其中一种设备是**Adafruit** I²C 双向逻辑电平转换模块，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/56cec6a4-4017-44e6-a92f-0c7477a90691.png)Adafruit I²C 双向逻辑电平转换模块

除了确保任何逻辑电压适合您使用的设备之外，它还将允许总线在更长的导线上延伸（电平转换器还将充当总线中继）。

# 仅使用 PCF8591 芯片或添加替代传感器

下图显示了 PCF8591 模块不带传感器的电路图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/74186137-d1fd-441d-ae48-799f6c5ef883.png)PCF8591 模块的电路图，不带传感器附件

如您所见，除了传感器外，只有五个额外的元件。我们有一个电源滤波电容（C1）和一个带有限流电阻（R5）的电源指示 LED（D2），所有这些都是可选的。

请注意，该模块包括两个 10K 上拉电阻（R8 和 R9）用于 SCL 和 SDA 信号。但是，由于树莓派上的 GPIO I²C 连接也包括上拉电阻，因此模块上不需要这些电阻（并且可以被移除）。这也意味着我们应该只将该模块连接到 VCC = 3.3V（如果我们使用 5V，则 SCL 和 SDA 上的电压将约为 3.56V，这对于树莓派的 GPIO 引脚来说太高）。

PCF891 模块上的传感器都是电阻性的，因此模拟输入上的电压电平将随着传感器电阻的变化在 GND 和 VCC 之间变化：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/c955d053-69ec-4060-a84d-a776759f5e74.png)电位分压电路。这提供了与传感器电阻成比例的电压。

该模块使用一种称为电位分压器的电路。顶部的电阻平衡了底部传感器提供的电阻，以提供介于**VCC**和**GND**之间的电压。

电位器的输出电压（*V[out]*）可以计算如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/f5739d01-f1d4-4ce7-b689-dbd73ca2705b.png)

R[t]和 R[b]分别是顶部和底部的电阻值，VCC 是供电电压。

模块中的电位器具有 10K 欧姆的电阻，根据调节器的位置在顶部和底部之间分割。因此，在中间，我们在每一侧都有 5K 欧姆和输出电压为 1.65V；四分之一的位置（顺时针），我们有 2.5K 欧姆和 7.5K 欧姆，产生 0.825V。

我没有显示 AOUT 电路，它是一个电阻和 LED。但是，正如您将发现的，LED 不适合指示模拟输出（除了显示开/关状态）。

对于更敏感的电路，您可以使用更复杂的电路，例如**惠斯通电桥**（它允许检测电阻的微小变化），或者您可以使用专用传感器，根据其读数输出模拟电压（例如**TMP36**温度传感器）。PCF891 还支持差分输入模式，其中一个通道的输入可以与另一个通道的输入进行比较（结果读数将是两者之间的差异）。

有关 PCF8591 芯片的更多信息，请参阅[`www.nxp.com/documents/data_sheet/PCF8591.pdf`](http://www.nxp.com/documents/data_sheet/PCF8591.pdf)上的数据表。

# 使用模拟数字转换器读取模拟数据

在命令行中使用的 I²C 工具（在上一节中使用）对于调试 I²C 设备非常有用，但对于 Python 来说并不实用，因为它们会很慢并且需要大量的开销。幸运的是，有几个 Python 库提供了 I²C 支持，允许有效地使用 I²C 与连接的设备进行通信并提供简单的操作。

我们将使用这样的库来创建我们自己的 Python 模块，它将允许我们快速轻松地从 ADC 设备获取数据并在我们的程序中使用它。该模块设计得非常灵活，可以在不影响其余示例的情况下放置其他硬件或数据源。

# 准备工作

要使用 Python 3 使用 I²C 总线，我们将使用*Gordon Henderson 的* WiringPi2（有关更多详细信息，请参见[`wiringpi.com/`](http://wiringpi.com/)）。

安装`wiringpi2`的最简单方法是使用 Python 3 的`pip`。`pip`是 Python 的软件包管理器，其工作方式类似于`apt-get`。您希望安装的任何软件包都将从在线存储库自动下载并安装。

要安装`pip`，请使用以下命令：

```py
sudo apt-get install python3-dev python3-pip  
```

然后，使用以下命令安装`wiringpi2`：

```py
sudo pip-3.2 install wiringpi2
```

安装完成后，您应该看到以下内容，表示成功：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/e0d4f643-b6ce-4174-8a8c-023b23a47d99.png)成功安装 WiringPi2

您需要将 PCF8591 模块连接到树莓派的 I²C 连接上，就像之前使用的那样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/c3aa40b6-c765-446b-b1d2-7941f47ea5df.png)PCF8591 模块和引脚连接到树莓派 GPIO 连接器

# 如何做...

在下一节中，我们将编写一个脚本，以便我们可以收集数据，然后稍后在本章中使用。

创建以下脚本`data_adc.py`，如下所示：

1.  首先，导入我们将使用的模块并创建变量，如下所示：

```py
#!/usr/bin/env python3 
#data_adc.py 
import wiringpi2 
import time 

DEBUG=False 
LIGHT=0;TEMP=1;EXT=2;POT=3 
ADC_CH=[LIGHT,TEMP,EXT,POT] 
ADC_ADR=0x48 
ADC_CYCLE=0x04 
BUS_GAP=0.25 
DATANAME=["0:Light","1:Temperature", 
          "2:External","3:Potentiometer"] 
```

1.  创建`device`类并使用构造函数进行初始化，如下所示：

```py
class device: 
  # Constructor: 
  def __init__(self,addr=ADC_ADR): 
    self.NAME = DATANAME 
    self.i2c = wiringpi2.I2C() 
    self.devADC=self.i2c.setup(addr) 
    pwrup = self.i2c.read(self.devADC) #flush powerup value 
    if DEBUG==True and pwrup!=-1: 
      print("ADC Ready") 
    self.i2c.read(self.devADC) #flush first value 
    time.sleep(BUS_GAP) 
    self.i2c.write(self.devADC,ADC_CYCLE) 
    time.sleep(BUS_GAP) 
    self.i2c.read(self.devADC) #flush first value 
```

1.  在类中，定义一个函数以提供通道名称列表，如下所示：

```py
def getName(self): 
  return self.NAME
```

1.  定义另一个函数（仍然作为类的一部分）以返回 ADC 通道的新样本集，如下所示：

```py
def getNew(self): 
  data=[] 
  for ch in ADC_CH: 
    time.sleep(BUS_GAP) 
    data.append(self.i2c.read(self.devADC)) 
  return data 
```

1.  最后，在设备类之后，创建一个测试函数来测试我们的新`device`类，如下所示。这只能在直接执行脚本时运行：

```py
def main(): 
  ADC = device(ADC_ADR) 
  print (str(ADC.getName())) 
  for i in range(10): 
    dataValues = ADC.getNew() 
    print (str(dataValues)) 
    time.sleep(1) 

if __name__=='__main__': 
  main() 
#End 
```

您可以使用以下命令运行此模块的测试函数：

```py
sudo python3 data_adc.py  
```

# 工作原理...

我们首先导入`wiringpi2`，以便稍后可以与我们的 I²C 设备通信。我们将创建一个类来包含控制 ADC 所需的功能。创建类时，我们可以初始化`wiringpi2`，使其准备好使用 I²C 总线（使用`wiringpi2.I2C()`），并使用芯片的总线地址设置一个通用 I²C 设备（使用`self.i2c.setup(0x48)`）。

`wiringpi2`还有一个专用类，可与 PCF8591 芯片一起使用；但是，在这种情况下，更有用的是使用标准 I²C 功能来说明如何使用`wiringpi2`控制任何 I²C 设备。通过参考设备数据表，您可以使用类似的命令与任何连接的 I²C 设备进行通信（无论是否直接支持）。

与以前一样，我们执行设备读取并配置 ADC 以循环通过通道，但是我们使用`wiringpi2`的`I2C`对象的`read`和`write`函数，而不是`i2cget`和`i2cset`。初始化后，设备将准备好读取每个通道上的模拟信号。

该类还将有两个成员函数。第一个函数`getName()`返回一个通道名称列表（我们可以用它来将数据与其来源进行关联），第二个函数`getNew()`返回所有通道的新数据集。数据是使用`i2c.read()`函数从 ADC 读取的，由于我们已经将其放入循环模式，每次读取都将来自下一个通道。

由于我们计划稍后重用此类，因此我们将使用`if __name__`测试来允许我们定义在直接执行文件时要运行的代码。在我们的`main()`函数中，我们创建 ADC，这是我们新设备类的一个实例。如果需要，我们可以选择选择非默认地址；否则，将使用芯片的默认地址。我们使用`getName()`函数打印出通道的名称，然后我们可以从`ADC`（使用`getNew()`）收集数据并显示它们。

# 还有更多...

以下允许我们在`data_adc.py`中定义设备类的另一个版本，以便可以在 ADC 模块的位置使用它。这将允许在本章的其余部分中尝试而无需任何特定的硬件。

# 无硬件收集模拟数据

如果您没有可用的 ADC 模块，则可以从树莓派内部获得大量可用数据，可以代替使用。

创建`data_local.py`脚本如下：

```py
#!/usr/bin/env python3 
#data_local.py 
import subprocess 
from random import randint 
import time 

MEM_TOTAL=0 
MEM_USED=1 
MEM_FREE=2 
MEM_OFFSET=7 
DRIVE_USED=0 
DRIVE_FREE=1 
DRIVE_OFFSET=9 
DEBUG=False 
DATANAME=["CPU_Load","System_Temp","CPU_Frequency", 
          "Random","RAM_Total","RAM_Used","RAM_Free", 
          "Drive_Used","Drive_Free"] 

def read_loadavg(): 
  # function to read 1 minute load average from system uptime 
  value = subprocess.check_output( 
            ["awk '{print $1}' /proc/loadavg"], shell=True) 
  return float(value) 

def read_systemp(): 
  # function to read current system temperature 
  value = subprocess.check_output( 
            ["cat /sys/class/thermal/thermal_zone0/temp"], 
            shell=True) 
  return int(value) 

def read_cpu(): 
  # function to read current clock frequency 
  value = subprocess.check_output( 
            ["cat /sys/devices/system/cpu/cpu0/cpufreq/"+ 
             "scaling_cur_freq"], shell=True) 
  return int(value) 

def read_rnd(): 
  return randint(0,255) 

def read_mem(): 
  # function to read RAM info 
  value = subprocess.check_output(["free"], shell=True) 
  memory=[] 
  for val in value.split()[MEM_TOTAL+ 
                           MEM_OFFSET:MEM_FREE+ 
                           MEM_OFFSET+1]: 
    memory.append(int(val)) 
  return(memory) 

def read_drive(): 
  # function to read drive info 
  value = subprocess.check_output(["df"], shell=True) 
  memory=[] 
  for val in value.split()[DRIVE_USED+ 
                           DRIVE_OFFSET:DRIVE_FREE+ 
                           DRIVE_OFFSET+1]: 
    memory.append(int(val)) 
  return(memory) 

class device: 
  # Constructor: 
  def __init__(self,addr=0): 
    self.NAME=DATANAME 

  def getName(self): 
    return self.NAME 

  def getNew(self): 
    data=[] 
    data.append(read_loadavg()) 
    data.append(read_systemp()) 
    data.append(read_cpu()) 
    data.append(read_rnd()) 
    memory_ram = read_mem() 
    data.append(memory_ram[MEM_TOTAL]) 
    data.append(memory_ram[MEM_USED]) 
    data.append(memory_ram[MEM_FREE]) 
    memory_drive = read_drive() 
    data.append(memory_drive[DRIVE_USED]) 
    data.append(memory_drive[DRIVE_FREE]) 
    return data 

def main(): 
  LOCAL = device() 
  print (str(LOCAL.getName())) 
  for i in range(10): 
    dataValues = LOCAL.getNew() 
    print (str(dataValues)) 
    time.sleep(1) 

if __name__=='__main__': 
  main() 
#End 
```

前面的脚本允许我们使用以下命令从树莓派中收集系统信息（`subprocess`模块允许我们捕获结果并处理它们）：

+   CPU 速度：

```py
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq  
```

+   CPU 负载：

```py
awk '{print $1}' /proc/loadavg
```

+   核心温度（乘以 1,000）：

```py
cat /sys/class/thermal/thermal_zone0/temp  
```

+   驱动器信息：

```py
df  
```

+   RAM 信息：

```py
free  
```

每个数据项都是使用其中一个函数进行采样的。在驱动和 RAM 信息的情况下，我们将响应拆分为一个列表（由空格分隔），并选择我们想要监视的项目（如可用内存和已用驱动器空间）。

这一切都打包成与`data_adc.py`文件和`device`类相同的方式运行（因此您可以选择在以下示例中使用`data_adc`包括或`data_local`包括，只需将`data_adc`包括替换为`data_local`）。

# 记录和绘制数据

现在我们能够采样和收集大量数据，重要的是我们能够捕获和分析它。为此，我们将使用一个名为`matplotlib`的 Python 库，其中包含许多有用的工具来操作、绘制和分析数据。我们将使用`pyplot`（它是`matplotlib`的一部分）来生成我们捕获数据的图表。有关`pyplot`的更多信息，请访问[`matplotlib.org/users/pyplot_tutorial.html`](http://matplotlib.org/users/pyplot_tutorial.html)。

这是一个用于 Python 的类似 MATLAB 的数据可视化框架。

# 准备工作

要使用`pyplot`，我们需要安装`matplotlib`。

由于`matplotlib`安装程序存在问题，使用`pip-3.2`进行安装并不总是正确的。以下方法将通过手动执行`pip`的所有步骤来克服这个问题；然而，这可能需要超过 30 分钟才能完成。

为节省时间，您可以尝试使用`pip`安装，这样会快得多。如果不起作用，您可以使用前面提到的手动方法进行安装。

使用以下命令尝试使用`pip`安装`matplotlib`：

`  sudo apt-get install tk-dev python3-tk libpng-dev`

`  sudo pip-3.2 install numpy`

`  sudo pip-3.2 install matplotlib`

您可以通过运行`python3`并尝试从 Python 终端导入它来确认`matplotlib`已安装，如下所示：

```py
import matplotlib  
```

如果安装失败，它将以以下方式响应：

`  ImportError: No module named matplotlib`

否则，将不会有错误。

使用以下步骤手动安装`matplotlib`：

1.  安装支持包如下：

```py
sudo apt-get install tk-dev python3-tk python3-dev libpng-dev
sudo pip-3.2 install numpy
sudo pip-3.2 install matplotlib  
```

1.  从 Git 存储库下载源文件（命令应为单行）如下：

```py
wget https://github.com/matplotlib/matplotlib/archive/master.zip
```

1.  解压并打开创建的`matplotlib-master`文件夹，如下所示：

```py
unzip master.zip
rm master.zip
cd matplotlib-master
```

1.  运行设置文件进行构建（这将需要一段时间）并安装如下：

```py
sudo python3 setup.py build
sudo python3 setup.py install  
```

1.  以与自动安装相同的方式测试安装。

我们要么需要 PCF8591 ADC 模块（和之前安装的`wiringpi2`），要么我们可以使用上一节中的`data_local.py`模块（只需在脚本的导入部分用`data_local`替换`data_adc`）。我们还需要在新脚本的同一目录中拥有`data_adc.py`和`data_local.py`，具体取决于您使用哪个。

# 如何做...

1.  创建一个名为`log_adc.py`的脚本：

```py
#!/usr/bin/python3 
#log_adc.c 
import time 
import datetime 
import data_adc as dataDevice 

DEBUG=True 
FILE=True 
VAL0=0;VAL1=1;VAL2=2;VAL3=3 #Set data order 
FORMATHEADER = "t%st%st%st%st%s" 
FORMATBODY = "%dt%st%ft%ft%ft%f" 

if(FILE):f = open("data.log",'w') 

def timestamp(): 
  ts = time.time()  
  return datetime.datetime.fromtimestamp(ts).strftime( 
                                    '%Y-%m-%d %H:%M:%S') 

def main(): 
    counter=0 
    myData = dataDevice.device() 
    myDataNames = myData.getName() 
    header = (FORMATHEADER%("Time", 
                        myDataNames[VAL0],myDataNames[VAL1], 
                        myDataNames[VAL2],myDataNames[VAL3])) 
    if(DEBUG):print (header) 
    if(FILE):f.write(header+"n") 
    while(1): 
      data = myData.getNew() 
      counter+=1 
      body = (FORMATBODY%(counter,timestamp(), 
                        data[0],data[1],data[2],data[3])) 
      if(DEBUG):print (body) 
      if(FILE):f.write(body+"n") 
      time.sleep(0.1) 

try: 
  main() 
finally: 
  f.close() 
#End 
```

1.  创建一个名为`log_graph.py`的第二个脚本，如下所示：

```py
#!/usr/bin/python3 
#log_graph.py 
import numpy as np 
import matplotlib.pyplot as plt 

filename = "data.log" 
OFFSET=2 
with open(filename) as f: 
    header = f.readline().split('t') 

data = np.genfromtxt(filename, delimiter='t', skip_header=1, 
                    names=['sample', 'date', 'DATA0', 
                           'DATA1', 'DATA2', 'DATA3']) 
fig = plt.figure(1) 
ax1 = fig.add_subplot(211)#numrows, numcols, fignum 
ax2 = fig.add_subplot(212) 
ax1.plot(data['sample'],data['DATA0'],'r', 
         label=header[OFFSET+0]) 
ax2.plot(data['sample'],data['DATA1'],'b', 
         label=header[OFFSET+1]) 
ax1.set_title("ADC Samples")     
ax1.set_xlabel('Samples') 
ax1.set_ylabel('Reading') 
ax2.set_xlabel('Samples') 
ax2.set_ylabel('Reading') 

leg1 = ax1.legend() 
leg2 = ax2.legend() 

plt.show() 
#End 
```

# 它是如何工作的...

第一个脚本`log_adc.py`允许我们收集数据并将其写入日志文件。

我们可以通过导入`data_adc`作为`dataDevice`来使用 ADC 设备，或者我们可以导入`data_local`来使用系统数据。给`VAL0`到`VAL3`赋予的数字允许我们改变通道的顺序（如果使用`data_local`设备，则选择其他通道）。我们还可以定义头文件和日志文件中每行的格式字符串（使用`%s`，`%d`和`%f`来允许我们替换字符串，整数和浮点值），如下表所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/dc5e9dc1-c3b0-43e5-be73-bcce7a60ad1d.png)从 ADC 传感器模块捕获的数据表

在记录到文件时（当`FILE=True`时），我们使用`'w'`选项以写模式打开`data.log`（这将覆盖任何现有文件；要追加到文件，请使用`'a'`）。

作为我们的数据日志的一部分，我们使用`time`和`datetime`生成`timestamp`来获取当前的**epoch 时间**（这是自 1970 年 1 月 1 日以来的毫秒数），使用`time.time()`命令。我们使用`strftime()`将值转换为更友好的`年-月-日 时:分:秒`格式。

`main()`函数首先创建我们的`device`类的一个实例（我们在前面的示例中创建了这个类），它将提供数据。我们从`data`设备获取通道名称并构造`header`字符串。如果`DEBUG`设置为`True`，数据将打印到屏幕上；如果`FILE`设置为`True`，它将被写入文件。

在主循环中，我们使用设备的`getNew()`函数来收集数据并格式化以在屏幕上显示或记录到文件中。使用`try: finally:`命令调用`main()`函数，这将确保在脚本中止时，文件将被正确关闭。

第二个脚本`log_graph.py`允许我们读取日志文件并生成记录的数据的图表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/ec2f4f51-eed4-46d3-8679-b60c386d6df6.png)由 log_graph.py 从光线和温度传感器产生的图表

我们首先打开日志文件并读取第一行；这包含头信息（然后我们可以用来在以后识别数据）。接下来，我们使用`numpy`，这是一个专门的 Python 库，扩展了我们可以操作数据和数字的方式。在这种情况下，我们使用它来从文件中读取数据，根据制表符分割数据，并为每个数据通道提供标识符。

我们定义一个图形来保存我们的图表，添加两个子图（位于 2 x 1 网格中的位置 1 和 2 - 由值`211`和`212`设置）。接下来，我们定义我们要绘制的值，提供`x`值（`data['sample']`），`y`值（`data['DATA0']`），`color`值（`'r'`表示`红色`或`'b'`表示`蓝色`），和`label`（设置为我们之前从文件顶部读取的标题文本）。

最后，我们为每个子图设置标题和`x`和`y`标签，启用图例（显示标签），并显示图表（使用`plt.show()`）。

# 还有更多...

现在我们有了查看我们一直在捕获的数据的能力，我们可以通过在采样时显示它来进一步扩展。这将使我们能够立即看到数据对环境或刺激变化的反应。我们还可以校准我们的数据，以便我们可以分配适当的缩放来产生实际单位的测量值。

# 绘制实时数据

除了从文件中绘制数据，我们还可以使用`matplotlib`来绘制传感器数据的采样。为此，我们可以使用`plot-animation`功能，它会自动调用一个函数来收集新数据并更新我们的图表。

创建以下脚本，名为`live_graph.py`：

```py
#!/usr/bin/python3 
#live_graph.py 
import numpy as np 
import matplotlib.pyplot as plt 
import matplotlib.animation as animation 
import data_local as dataDevice 

PADDING=5 
myData = dataDevice.device() 
dispdata = [] 
timeplot=0 
fig, ax = plt.subplots() 
line, = ax.plot(dispdata) 

def update(data): 
  global dispdata,timeplot 
  timeplot+=1 
  dispdata.append(data) 
  ax.set_xlim(0, timeplot) 
  ymin = min(dispdata)-PADDING 
  ymax = max(dispdata)+PADDING 
  ax.set_ylim(ymin, ymax) 
  line.set_data(range(timeplot),dispdata) 
  return line 

def data_gen(): 
  while True: 
    yield myData.getNew()[1]/1000 

ani = animation.FuncAnimation(fig, update,  
                              data_gen, interval=1000) 
plt.show() 
#End 
```

我们首先定义我们的`dataDevice`对象并创建一个空数组`dispdata[]`，它将保存所有已收集的数据。接下来，我们定义我们的子图和我们要绘制的线。

`FuncAnimation()`函数允许我们通过定义更新函数和生成器函数来更新图形（`fig`）。生成器函数（`data_gen()`）将在每个间隔（1,000 毫秒）调用，并产生一个数据值。

此示例使用核心温度读数，当除以 1,000 时，会给出实际的温度（以`degC`为单位）。

要使用 ADC 数据，将`dataDevice`的导入更改为`data_adc`，并调整以下行以使用通道而不是`[1]`，并应用不同于 1,000 的缩放：

`yield myData.getNew()[1]/1000`

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/f4dabe2e-4897-4ffd-9f8d-d95e6260dee1.png)树莓派实时绘图

数据值传递给`update()`函数，这允许我们将其添加到将包含要在图中显示的所有数据值的`dispdata[]`数组中。我们调整*x*轴范围，使其接近数据的`min`和`max`值。我们还调整*y*轴，以便在继续采样更多数据时继续增长。

`FuncAnimation()`函数需要`data_gen()`对象是一种称为`generator`的特殊类型的函数。`generator`函数每次被调用时都会产生一系列连续的值，甚至可以使用其先前的状态来计算下一个值（如果需要的话）。这用于执行连续的计算以进行绘图；这就是为什么它在这里使用的原因。在我们的情况下，我们只想连续运行相同的采样函数（`new_data()`），以便每次调用它时，它都会产生一个新的样本。

最后，我们使用`dispdata[]`数组（使用`set_data()`函数）更新*x*和*y*轴数据，这将使我们的样本根据我们进行采样的秒数进行绘制。要使用其他数据，或者绘制来自 ADC 的数据，请调整`dataDevice`的导入，并在`data_gen()`函数中选择所需的通道（和缩放）。

# 缩放和校准数据

您可能已经注意到，有时很难解释从 ADC 读取的数据，因为该值只是一个数字。一个数字本身并没有太多帮助；它只能告诉您环境比上一个样本稍微热一些或稍微暗一些。但是，如果您可以使用另一个设备提供可比较的值（例如当前室温），那么您可以校准传感器数据以提供更有用的真实世界信息。

为了获得粗略的校准，我们将使用两个样本创建一个线性拟合模型，然后可以用于估计其他 ADC 读数的真实世界值（这假设传感器本身在其响应中大部分是线性的）。以下图表显示了使用 25 和 30 摄氏度的两个读数创建的线性拟合图，为其他温度提供了估计的 ADC 值：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/47102c86-e5f9-4c4d-b4ac-f5f297865ded.png)样本用于线性校准温度传感器读数

我们可以使用以下函数来计算我们的模型：

```py
def linearCal(realVal1,readVal1,realVal2,readVal2): 
  #y=Ax+C 
  A = (realVal1-realVal2)/(readVal1-readVal2) 
  C = realVal1-(readVal1*A) 
  cal = (A,C) 
  return cal 
```

这将返回`cal`，其中将包含模型斜率（`A`）和偏移（`C`）。

然后我们可以使用以下函数通过使用该通道的计算`cal`值来计算任何读数的值：

```py
def calValue(readVal,cal = [1,0]): 
  realVal = (readVal*cal[0])+cal[1] 
  return realVal 
```

为了更准确，您可以进行多次采样，并在值之间进行线性插值（或将数据拟合到其他更复杂的数学模型），如果需要的话。

# 使用 I/O 扩展器扩展树莓派 GPIO

正如我们所看到的，利用更高级别的总线协议可以让我们快速轻松地连接到更复杂的硬件。通过使用 I²C，我们可以将树莓派上可用的 I/O 扩展，并提供额外的电路保护（在某些情况下，还提供额外的电源来驱动更多的硬件）。

有许多可用的设备可以通过 I²C 总线（以及 SPI）进行 I/O 扩展，但最常用的是 28 引脚设备 MCP23017，它提供 16 个额外的数字输入/输出引脚。作为 I²C 设备，它只需要两个信号（SCL 和 SDA 连接，加上地和电源），并且可以与同一总线上的其他 I²C 设备一起正常工作。

我们将看到 Adafruit I²C 16x2 RGB LCD Pi Plate 如何利用这些芯片来通过 I²C 总线控制 LCD 字母显示和键盘（如果没有 I/O 扩展器，这通常需要多达 15 个 GPIO 引脚）。

其他制造商的板也可以使用。16x2 LCD 模块和 I²C 到串行接口模块可以组合在一起，以拥有我们自己的低成本 I²C LCD 模块。

# 做好准备

您将需要 Adafruit I²C 16x2 RGB LCD Pi Plate（还包括五个键盘按钮），如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/ae827aa6-e260-42a8-a195-2a15b0ca1d68.png)带有键盘按钮的 Adafruit I²C 16x2 RGB LCD Pi Plate

Adafruit I²C 16x2 RGB LCD Pi Plate 直接连接到树莓派的 GPIO 连接器。

与之前一样，我们可以使用 PCF8591 ADC 模块，或者使用上一节中的`data_local.py`模块（在脚本的导入部分使用`data_adc`或`data_local`）。`data_adc.py`和`data_local.py`文件应该与新脚本在同一个目录中。

LCD Pi Plate 只需要四个引脚（SDA、SCL、GND 和 5V）；它连接整个 GPIO 引脚。如果我们想要将其与其他设备一起使用，例如 PCF8591 ADC 模块，那么可以使用类似于 PiBorg 的 TriBorg（将 GPIO 端口分成三个）来添加端口。

# 操作步骤...

1.  创建以下脚本，名为`lcd_i2c.py`：

```py
#!/usr/bin/python3 
#lcd_i2c.py 
import wiringpi2 
import time 
import datetime 
import data_local as dataDevice 

AF_BASE=100 
AF_E=AF_BASE+13;     AF_RW=AF_BASE+14;   AF_RS=AF_BASE+15 
AF_DB4=AF_BASE+12;   AF_DB5=AF_BASE+11;  AF_DB6=AF_BASE+10 
AF_DB7=AF_BASE+9 

AF_SELECT=AF_BASE+0; AF_RIGHT=AF_BASE+1; AF_DOWN=AF_BASE+2 
AF_UP=AF_BASE+3;     AF_LEFT=AF_BASE+4;  AF_BACK=AF_BASE+5 

AF_GREEN=AF_BASE+6;  AF_BLUE=AF_BASE+7;  AF_RED=AF_BASE+8 
BNK=" "*16 #16 spaces 

def gpiosetup(): 
  global lcd 
  wiringpi2.wiringPiSetup() 
  wiringpi2.mcp23017Setup(AF_BASE,0x20) 
  wiringpi2.pinMode(AF_RIGHT,0) 
  wiringpi2.pinMode(AF_LEFT,0) 
  wiringpi2.pinMode(AF_SELECT,0) 
  wiringpi2.pinMode(AF_RW,1) 
  wiringpi2.digitalWrite(AF_RW,0) 
  lcd=wiringpi2.lcdInit(2,16,4,AF_RS,AF_E, 
                        AF_DB4,AF_DB5,AF_DB6,AF_DB7,0,0,0,0) 

def printLCD(line0="",line1=""): 
  wiringpi2.lcdPosition(lcd,0,0) 
  wiringpi2.lcdPrintf(lcd,line0+BNK) 
  wiringpi2.lcdPosition(lcd,0,1) 
  wiringpi2.lcdPrintf(lcd,line1+BNK) 

def checkBtn(idx,size): 
  global run 
  if wiringpi2.digitalRead(AF_LEFT): 
    idx-=1 
    printLCD() 
  elif wiringpi2.digitalRead(AF_RIGHT): 
    idx+=1 
    printLCD() 
  if wiringpi2.digitalRead(AF_SELECT): 
    printLCD("Exit Display") 
    run=False 
  return idx%size 

def main(): 
  global run 
  gpiosetup() 
  myData = dataDevice.device() 
  myDataNames = myData.getName() 
  run=True 
  index=0 
  while(run): 
    data = myData.getNew() 
    printLCD(myDataNames[index],str(data[index])) 
    time.sleep(0.2) 
    index = checkBtn(index,len(myDataNames)) 

main() 
#End 
```

1.  连接 LCD 模块后，按以下方式运行脚本：

```py
sudo python3 lcd_i2c.py  
```

使用左右按钮选择要显示的数据通道，然后按 SELECT 按钮退出。

# 工作原理...

`wiringpi2`库对于 I/O 扩展器芯片（如 Adafruit LCD 字符模块所使用的芯片）有很好的支持。要使用 Adafruit 模块，我们需要为 MCP23017 端口 A 的所有引脚设置引脚映射，如下表所示（然后，我们使用偏移量`100`设置 I/O 扩展器引脚）：

| **名称** | **SELECT** | **RIGHT** | **DOWN** | **UP** | **LEFT** | **GREEN** | **BLUE** | **RED** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MCP23017 端口 A | A0 | A1 | A2 | A3 | A4 | A6 | A7 | A8 |
| WiringPi 引脚 | 100 | 101 | 102 | 103 | 104 | 106 | 107 | 108 |

MCP23017 端口 B 的所有引脚的引脚映射如下：

| **名称** | **DB7** | **DB6** | **DB5** | **DB4** | **E** | **RW** | **RS** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MCP23017 端口 B | B1 | B2 | B3 | B4 | B5 | B6 | B7 |
| WiringPi 引脚 | 109 | 110 | 111 | 112 | 113 | 114 | 115 |

要设置 LCD 屏幕，我们初始化`wiringPiSetup()`和 I/O 扩展器`mcp23017Setup()`。然后，我们指定 I/O 扩展器的引脚偏移和总线地址。接下来，我们将所有硬件按钮设置为输入（使用`pinMode(引脚号,0)`），并将 LCD 的 RW 引脚设置为输出。`wiringpi2` LCD 库期望 RW 引脚设置为`LOW`（将其强制设置为只读模式），因此我们将引脚设置为`LOW`（使用`digitalWrite(AF_RW,0)`）。

我们通过定义屏幕的行数和列数以及说明我们是否使用 4 位或 8 位数据模式（我们使用 8 个数据线中的 4 个，因此将使用 4 位模式）来创建一个`lcd`对象。我们还提供了我们使用的引脚的引脚映射（最后四个设置为`0`，因为我们只使用四个数据线）。

现在，我们将创建一个名为`PrintLCD()`的函数，它将允许我们发送字符串以显示在显示器的每一行上。我们使用`lcdPosition()`为每一行设置`lcd`对象上的光标位置，然后打印每一行的文本。我们还在每一行的末尾添加一些空格，以确保整行被覆盖。

下一个函数`checkBtn()`，简要检查左右和选择按钮是否已被按下（使用`digitalRead()`函数）。如果按下了左/右按钮，则将索引设置为数组中的上一个/下一个项目。如果按下了 SELECT 按钮，则将`run`标志设置为`False`（这将退出主循环，允许脚本完成）。

`main()`函数调用`gpiosetup()`来创建我们的`lcd`对象；然后，我们创建我们的`dataDevice`对象并获取数据名称。在主循环中，我们获取新数据；然后，我们使用我们的`printLCD()`函数在顶部行上显示数据名称，并在第二行上显示数据值。最后，我们检查按钮是否已被按下，并根据需要设置索引到我们的数据。

# 还有更多...

使用诸如 MCP23017 之类的扩展器芯片提供了一种增加与树莓派的硬件连接性的绝佳方式，同时还提供了额外的保护层（更换扩展器芯片比更换树莓派便宜）。

# I/O 扩展器的电压和限制

扩展器在使用时只使用少量功率，但如果您使用 3.3V 供电，那么您仍然只能从所有引脚中最多吸取 50mA。如果吸取的功率过多，那么您可能会遇到系统冻结或 SD 卡上的读/写损坏。

如果您使用 5V 供电扩展器，那么您可以吸取扩展器支持的最大功率（每个引脚最多约 25mA，总共 125mA），只要您的 USB 电源供应足够强大。

我们必须记住，如果扩展器使用 5V 电源供电，输入/输出和中断线也将是 5V，绝不能连接回树莓派（除非使用电平转换器将电压转换为 3.3V）。

通过更改扩展器芯片上的地址引脚（A0、A1 和 A2）的接线，最多可以同时在同一 I²C 总线上使用八个模块。为了确保每个模块都有足够的电流可用，我们需要使用单独的 3.3V 供电。像 LM1117-3.3 这样的线性稳压器将是合适的（这将提供最多 800mA 的 3.3V，每个 100mA），并且只需要以下简单的电路：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/f17c86f4-937c-42b6-a2b7-9bbe74e089a4.png)LM1117 线性稳压器电路

以下图表显示了如何将稳压器连接到 I/O 扩展器（或其他设备）以为驱动额外硬件提供更多电流：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/596bf4cd-d3a3-4ac6-a961-c7aabfe61b8b.png)使用稳压器与树莓派

输入电压（Vin）由树莓派提供（例如，来自 GPIO 引脚头，如 5V 引脚 2）。但是，只要在 4.5V 和 15V 之间并且能够提供足够的电流，Vin 可以由任何其他电源（或电池组）提供。重要的是要确保树莓派、电源（如果使用单独的电源）、稳压器和 I/O 扩展器的地连接（GND）都连接在一起（作为公共地）。

# 使用您自己的 I/O 扩展器模块

您可以使用可用的 I/O 扩展器模块（或者只是以下电路中的 MCP23017 芯片）来控制大多数 HD44780 兼容的 LCD 显示器：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/418d237b-b8ec-45b3-b519-48ac23a76624.png)I/O 扩展器和 HD44780 兼容显示器

D-Pad 电路，*使用 Python 驱动硬件*，也可以连接到扩展器的剩余端口 A 引脚（`PA0`到按钮 1，`PA1`到右，`PA2`到下，`PA3`到上，`PA4`到左，`PA5`到按钮 2）。与前面的例子一样，按钮将是`PA0`到`PA4`（WiringPi 引脚编号 100 到 104）；除此之外，我们还将第二个按钮添加到`PA5`（WiringPi 引脚编号 105）。

# 直接控制 LCD 字母显示器

或者，您也可以直接从树莓派驱动屏幕，连接如下：

我们这里不使用 I²C 总线。

| **LCD** | **VSS** | **VDD** | **V0** | **RS** | **RW** | **E** | **DB4** | **DB5** | **DB6** | **DB7** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **LCD 引脚** | 1 | 2 | 3 | 4 | 5 | 6 | 11 | 12 | 13 | 14 |
| **树莓派 GPIO** | 6 (GND) | 2 (5V) | 对比度 | 11 | 13 (GND) | 15 | 12 | 16 | 18 | 22 |

上表列出了树莓派和 HD44780 兼容的字母显示模块之间所需的连接。

对比度引脚（V0）可以像以前一样连接到可变电阻器（一端连接到 5V 供电，另一端连接到 GND）；尽管根据屏幕的不同，您可能会发现可以直接连接到 GND/5V 以获得最大对比度。

`wiringpi2` LCD 库假定 RW 引脚连接到 GND（只读）；这样可以避免 LCD 直接连接到树莓派时发送数据的风险（这将是一个问题，因为屏幕由 5V 供电，并将使用 5V 逻辑发送数据）。

确保您使用新的`AF_XX`引用更新代码，并通过更改`gpiosetup()`函数中的设置来引用物理引脚号。我们还可以跳过 MCP23017 设备的设置。

看一下以下命令：

```py
wiringpi2.wiringPiSetup()
wiringpi2.mcp23017Setup(AF_BASE,0x20)  
```

用以下命令替换前面的命令：

```py
wiringpi.wiringPiSetupPhys()  
```

您可以看到，我们只需要更改引脚引用以在使用 I/O 扩展器和不使用它之间切换，这显示了`wiringpi2`实现的方便之处。

# 在 SQLite 数据库中捕获数据

数据库是存储大量结构化数据并保持访问和搜索特定数据能力的完美方式。**结构化查询语言**（**SQL**）是一套标准化的命令，用于更新和查询数据库。在本例中，我们将使用 SQLite（SQL 数据库系统的轻量级、独立实现）。

在本章中，我们将从 ADC（或本地数据源）中收集原始数据，并构建自己的数据库。然后，我们可以使用一个名为`sqlite3`的 Python 库将数据添加到数据库，然后查询它：

```py
   ##            Timestamp  0:Light  1:Temperature   2:External  3:Potentiometer 
    0 2015-06-16 21:30:51      225            212          122              216 
    1  2015-06-16 21:30:52      225            212          148              216 
    2  2015-06-16 21:30:53      225            212          113              216 
    3  2015-06-16 21:30:54      225            212          137              216 
    4  2015-06-16 21:30:55      225            212          142              216 
    5  2015-06-16 21:30:56      225            212          115              216 
    6  2015-06-16 21:30:57      225            212          149              216 
    7  2015-06-16 21:30:58      225            212          128              216 
    8  2015-06-16 21:30:59      225            212          123              216 
    9  2015-06-16 21:31:02      225            212          147              216  
```

# 准备工作

为了在数据库中捕获数据，我们将安装 SQLite，以便它可以与 Python 的`sqlite3`内置模块一起使用。使用以下命令安装 SQLite：

```py
sudo apt-get install sqlite3  
```

接下来，我们将执行一些基本的 SQLite 操作，以了解如何使用 SQL 查询。

直接运行 SQLite，使用以下命令创建一个新的`test.db`数据库文件：

```py
sqlite3 test.db
SQLite version 3.7.13 2012-06-11 02:05:22
Enter ".help" for instructions
Enter SQL statements terminated with a ";"
sqlite>  
```

这将打开一个 SQLite 控制台，在其中我们直接输入 SQL 命令。例如，以下命令将创建一个新表，添加一些数据，显示内容，然后删除表：

```py
CREATE TABLE mytable (info TEXT, info2 TEXT,);
INSERT INTO mytable VALUES ("John","Smith");
INSERT INTO mytable VALUES ("Mary","Jane");
John|Smith
Mary|Jane
DROP TABLE mytable;
.exit  
```

您将需要与以前的配方中*准备就绪*部分中详细描述的相同的硬件设置，使用 I²C 总线与设备配合使用。

# 操作步骤

创建以下脚本，名为`mysqlite_adc.py`：

```py
#!/usr/bin/python3 
#mysql_adc.py 
import sqlite3 
import datetime 
import data_adc as dataDevice 
import time 
import os 

DEBUG=True 
SHOWSQL=True 
CLEARDATA=False 
VAL0=0;VAL1=1;VAL2=2;VAL3=3 #Set data order 
FORMATBODY="%5s %8s %14s %12s %16s" 
FORMATLIST="%5s %12s %10s %16s %7s" 
DATEBASE_DIR="/var/databases/datasite/" 
DATEBASE=DATEBASE_DIR+"mydatabase.db" 
TABLE="recordeddata" 
DELAY=1 #approximate seconds between samples 

def captureSamples(cursor): 
    if(CLEARDATA):cursor.execute("DELETE FROM %s" %(TABLE)) 
    myData = dataDevice.device() 
    myDataNames=myData.getName() 

    if(DEBUG):print(FORMATBODY%("##",myDataNames[VAL0], 
                                myDataNames[VAL1],myDataNames[VAL2], 
                                myDataNames[VAL3])) 
    for x in range(10): 
        data=myData.getNew() 
        for i,dataName in enumerate(myDataNames): 
            sqlquery = "INSERT INTO %s (itm_name, itm_value) " %(TABLE) +  
                       "VALUES('%s', %s)"  
                        %(str(dataName),str(data[i])) 
            if (SHOWSQL):print(sqlquery) 
            cursor.execute(sqlquery) 

        if(DEBUG):print(FORMATBODY%(x, 
                                    data[VAL0],data[VAL1], 
                                    data[VAL2],data[VAL3])) 
        time.sleep(DELAY) 
    cursor.commit() 

def displayAll(connect): 
    sqlquery="SELECT * FROM %s" %(TABLE) 
    if (SHOWSQL):print(sqlquery) 
    cursor = connect.execute (sqlquery) 
    print(FORMATLIST%("","Date","Time","Name","Value")) 

    for x,column in enumerate(cursor.fetchall()): 
       print(FORMATLIST%(x,str(column[0]),str(column[1]), 
                         str(column[2]),str(column[3]))) 

def createTable(cursor): 
    print("Create a new table: %s" %(TABLE)) 
    sqlquery="CREATE TABLE %s (" %(TABLE) +  
             "itm_date DEFAULT (date('now','localtime')), " +  
             "itm_time DEFAULT (time('now','localtime')), " +  
             "itm_name, itm_value)"  
    if (SHOWSQL):print(sqlquery) 
    cursor.execute(sqlquery) 
    cursor.commit() 

def openTable(cursor): 
    try: 
        displayAll(cursor) 
    except sqlite3.OperationalError: 
        print("Table does not exist in database") 
        createTable(cursor) 
    finally: 
        captureSamples(cursor) 
        displayAll(cursor) 

try: 
    if not os.path.exists(DATEBASE_DIR): 
        os.makedirs(DATEBASE_DIR) 
    connection = sqlite3.connect(DATEBASE) 
    try: 
        openTable(connection) 
    finally: 
        connection.close() 
except sqlite3.OperationalError: 
    print("Unable to open Database") 
finally: 
    print("Done") 

#End 
```

如果您没有 ADC 模块硬件，可以通过将`dataDevice`模块设置为`data_local`来捕获本地数据。确保您在以下脚本的同一目录中拥有`data_local.py`（来自*读取模拟数据使用模数转换器*配方中*还有更多...*部分）：

`import data_local as dataDevice`

这将捕获本地数据（RAM、CPU 活动、温度等）到 SQLite 数据库，而不是 ADC 样本。

# 它是如何工作的...

当首次运行脚本时，它将创建一个名为`mydatabase.db`的新 SQLite 数据库文件，该文件将添加一个名为`recordeddata`的表。该表由`createTable()`生成，该函数运行以下 SQLite 命令：

```py
CREATE TABLE recordeddata 
( 
    itm_date DEFAULT (date('now','localtime')), 
    itm_time DEFAULT (time('now','localtime')), 
    itm_name, 
    itm_value 
) 
```

新表将包含以下数据项：

| **名称** | **描述** |
| --- | --- |
| `itm_date` | 用于存储数据样本的日期。创建数据记录时，当前日期（使用`date('now','localtime')`）被应用为默认值。 |
| `itm_time` | 用于存储数据样本的时间。创建数据记录时，当前时间（使用`time('now','localtime')`）被应用为默认值。 |
| `itm_name` | 用于记录样本的名称。 |
| `itm_value` | 用于保存采样值。 |

然后，我们使用与以前的*记录和绘图数据*配方中相同的方法从 ADC 中捕获 10 个数据样本（如`captureSamples()`函数中所示）。但是，这次，我们将使用以下 SQL 命令将捕获的数据添加到我们的新 SQLite 数据库表中（使用`cursor.execute(sqlquery)`应用）：

```py
INSERT INTO recordeddata 
    (itm_name, itm_value) VALUES ('0:Light', 210) 
```

当前日期和时间将默认添加到每个记录中。我们最终得到一组 40 条记录（每个 ADC 样本周期捕获 4 条记录），这些记录现在存储在 SQLite 数据库中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/b1090b4d-96d0-4c69-85ba-45afc253bfb8.png)已捕获并存储了八个 ADC 样本在 SQLite 数据库中

记录创建后，我们必须记得调用`cursor.commit()`，这将保存所有新记录到数据库中。

脚本的最后部分调用`displayAll()`，它将使用以下 SQL 命令：

```py
SELECT * FROM recordeddata 
```

这将选择`recordeddata`表中的所有数据记录，并且我们使用`cursor.fetch()`将所选数据提供为我们可以迭代的列表：

```py
for x,column in enumerate(cursor.fetchall()): 
    print(FORMATLIST%(x,str(column[0]),str(column[1]), 
                      str(column[2]),str(column[3]))) 
```

这使我们能够打印出数据库的全部内容，显示捕获的数据。

请注意，在此脚本中我们使用`try`、`except`和`finally`结构来尝试处理用户运行脚本时最有可能遇到的情况。

首先，我们确保如果数据库目录不存在，我们会创建它。接下来，我们尝试打开数据库文件；如果不存在数据库文件，此过程将自动创建一个新的数据库文件。如果这些初始步骤中的任何一个失败（例如因为它们没有读/写权限），我们就无法继续，因此我们报告无法打开数据库并简单地退出脚本。

接下来，我们尝试在数据库中打开所需的表并显示它。如果数据库文件是全新的，此操作将始终失败，因为它将是空的。但是，如果发生这种情况，我们只需捕获异常并在继续使用脚本将采样数据添加到表并显示它之前创建表。

这允许脚本优雅地处理潜在问题，采取纠正措施，然后平稳地继续。下次运行脚本时，数据库和表将已经存在，因此我们不需要第二次创建它们，并且我们可以将样本数据附加到同一数据库文件中的表中。

# 还有更多...

有许多可用的 SQL 服务器变体（如 MySQL、Microsoft SQL Server 和 PostgreSQL），但它们至少应该具有以下主要命令（或等效命令）：

```py
CREATE, INSERT, SELECT, WHERE, UPDATE, SET, DELETE, and DROP 
```

即使您选择使用与此处使用的 SQLite 不同的 SQL 服务器，您也应该发现 SQL 命令会相对类似。

# 创建表命令

`CREATE TABLE`命令用于通过指定列名来定义新表（还可以设置默认值，如果需要）。

```py
CREATE TABLE table_name ( 
    column_name1 TEXT,  
    column_name2 INTEGER DEFAULT 0, 
    column_name3 REAL ) 
```

上一个 SQL 命令将创建一个名为`table_name`的新表，其中包含三个数据项。一列将包含文本，其他整数（例如 1、3、-9），最后，一列将包含实数（例如 5.6、3.1749、1.0）。

# 插入命令

`INSERT`命令将向数据库中的表添加特定条目：

```py
INSERT INTO table_name (column_name1name1, column_name2name2, column_name3)name3) 
    VALUES ('Terry'Terry Pratchett', 6666, 27.082015)082015) 
```

这将把提供的值输入到表中相应的列中。

# SELECT 命令

`SELECT`命令允许我们从数据库表中指定特定列或列，返回带有数据的记录列表：

```py
SELECT column_name1, column_name2 FROM table_name 
```

它还可以允许我们选择所有项目，使用此命令：

```py
SELECT * FROM table_name 
```

# WHERE 命令

`WHERE`命令用于指定要选择、更新或删除的特定条目：

```py
SELECT * FROM table_name 
    WHERE column_name1= 'Terry Pratchett' 
```

这将`SELECT`任何`column_name1`匹配`'Terry Pratchett'`的记录。

# 更新命令

`UPDATE`命令将允许我们更改（`SET`）指定列中的数据值。我们还可以将其与`WHERE`命令结合使用，以限制应用更改的记录：

```py
UPDATE table_name 
    SET column_name2=49name2=49,column_name3=30name3=30.111997 
    WHERE column_name1name1= 'Douglas Adams'Adams'; 
```

# 删除命令

`DELETE`命令允许使用`WHERE`选择的任何记录从指定的表中删除。但是，如果选择整个表，使用`DELETE * FROM table_name`将删除表的全部内容：

```py
DELETE FROM table_name 
    WHERE columncolumn_name2=9999 
```

# 删除命令

`DROP`命令允许完全从数据库中删除表：

```py
DROP table_name  
```

请注意，这将永久删除存储在指定表和结构中的所有数据。

# 从您自己的 Web 服务器查看数据

收集和整理信息到数据库非常有帮助，但如果它被锁在数据库或文件中，它就没有太多用处。然而，如果我们允许存储的数据通过网页查看，它将更容易访问；我们不仅可以从其他设备查看数据，还可以在同一网络上与其他人分享。

我们将创建一个本地 web 服务器来查询和显示捕获的 SQLite 数据，并允许通过 PHP web 界面查看。这将允许数据不仅可以通过树莓派上的 web 浏览器查看，还可以在本地网络上的其他设备上查看，如手机或平板电脑：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/0722af98-22cb-45da-b77e-f039fb491c8d.png)通过 web 页面显示的 SQLite 数据库中捕获的数据

使用 web 服务器输入和显示信息是允许广泛用户与您的项目互动的强大方式。以下示例演示了一个可以为各种用途定制的 web 服务器设置。

# 准备工作

确保您已完成上一个步骤，以便传感器数据已被收集并存储在 SQLite 数据库中。我们需要安装一个 web 服务器（**Apache2**）并启用 PHP 支持以允许 SQLite 访问。

使用以下命令安装 web 服务器和 PHP：

```py
sudo apt-get update
sudo aptitude install apache2 php5 php5-sqlite  
```

`/var/www/`目录被 web 服务器使用；默认情况下，它将加载`index.html`（或`index.php`）- 否则，它将只显示目录中文件的链接列表。

要测试 web 服务器是否正在运行，请创建一个默认的`index.html`页面。为此，您需要使用`sudo`权限创建文件（`/var/www/`目录受到普通用户更改的保护）。使用以下命令：

```py
sudo nano /var/www/index.html  
```

创建带有以下内容的`index.html`：

```py
<h1>It works!</h1> 
```

关闭并保存文件（使用*Ctrl* + *X*，*Y*和*Enter*）。

如果您正在使用带屏幕的树莓派，您可以通过加载桌面来检查它是否正常工作：

```py
startx  
```

然后，打开 web 浏览器（**epiphany-browser**）并输入`http://localhost`作为地址。您应该看到以下测试页面，表明 web 服务器处于活动状态：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/8e497ae9-d176-410b-ae38-0bfc5a9b6181.png)树莓派浏览器显示位于 http://localhost 的测试页面

如果您远程使用树莓派或将其连接到您的网络，您还应该能够在网络上的另一台计算机上查看该页面。首先，确定树莓派的 IP 地址（使用`sudo hostname -I`），然后在 web 浏览器中使用此地址。您甚至可能发现您可以使用树莓派的实际主机名（默认情况下，这是`http://raspberrypi/`）。

如果您无法从另一台计算机上看到网页，请确保您没有启用防火墙（在计算机本身或路由器上）来阻止它。

接下来，我们可以测试 PHP 是否正常运行。我们可以创建一个名为`test.php`的网页，并确保它位于`/var/www/`目录中：

```py
<?php 
  phpinfo(); 
?>; 
```

用于查看 SQLite 数据库中数据的 PHP 网页具有以下细节：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/5e5b4d29-1b48-400f-b29b-292129ae3652.png)在 http://localhost/test.php 查看 test.php 页面

现在我们准备编写我们自己的 PHP 网页来查看 SQLite 数据库中的数据。

# 如何做...

1.  创建以下 PHP 文件并将它们保存在名为`/var/www/./`的 web 服务器目录中。

1.  使用以下命令创建 PHP 文件：

```py
sudo nano /var/www/show_data_lite.php

```

1.  `show_data_lite.php`文件应包含以下内容：

```py
<head> 
<title>DatabaseDatabase Data</title> 
<meta http-equiv="refresh" content="10" > 
</head> 
<body> 

Press button to remove the table data 
<br> 
<input type="button" onclick="location.href = 'del_data_lite.php';" value="Delete"> 
<br><br> 
<b>Recorded Data</b><br> 
<?php 
$db = new PDO("sqlite:/var/databases/datasitedatasite/mydatabase.db"); 
//SQL query 
$strSQL = "SELECT * FROM recordeddatarecordeddata WHERE itmitm_name LIKE '%'%temp%'"; 
//Execute the query 
$response = $db->query($strSQL); 
//Loop through the response 
while($column = $response->fetch()) 
{ 
   //Display the content of the response 
   echo $column[0] . " "; 
   echo $column[1] . " "; 
   echo $column[2] . " "; 
   echo $column[3] . "<br />"; 
} 
?> 
Done 
</body> 
</html>
```

1.  使用以下命令创建 PHP 文件：

```py
sudo nano /var/www/del_data_lite.php
<html>
<body>

Remove all the data in the table.
<br>
<?php
$db = new PDO("sqlite:/var/databases/datasitedatasite/mydatabase.db");
//SQL query
$strSQL = "DROPDROP TABLErecordeddata recordeddata";
//ExecuteExecute the query
$response = $db->query($strSQL);

if ($response == 1)
    {
      echo "Result: DELETED DATA";
    }
else
    {
      echo "Error: Ensure table exists and database directory is owned    
by www-data";
    }
?>
<br><br>
Press button to return to data display.
<br>
<input type="button" onclick="location.href = 'show'show_data_lite.php';" value="Return">

</body>
</html>     
```

为了使 PHP 代码能够删除数据库中的表，它需要被 web 服务器写入。使用以下命令允许它可写：

`sudo chown www-data /var/databases/datasite -R`

1.  如果您使用以下地址在 web 浏览器中打开`show_data_lite.php`文件，它将显示为一个网页：

```py
http://localhost/showshow_data_lite.php
```

1.  或者，您可以通过引用树莓派的 IP 地址（使用`hostname -I`确认 IP 地址）在网络中的另一台计算机上打开网页：

```py
http://192.168.1.101/showshow_data_lite.php 
```

您可能还可以使用主机名（默认情况下，这将使地址为`http://raspberrypi/show_data_lite.php`）。但是，这可能取决于您的网络设置。

如果没有数据，请确保运行`mysqlite_adc.py`脚本以捕获额外的数据。

1.  要使`show_data_lite.php`页面在访问树莓派的网址时自动显示（而不是*It works!*页面），我们可以将`index.html`更改为以下内容：

```py
<meta http-equiv="refresh" content="0; URL='show_data_lite.php' " /> 
```

这将自动将浏览器重定向到加载我们的`show_data_lite.php`页面。

# 工作原理...

`show_data_lite.php`文件将显示存储在 SQLite 数据库中的温度数据（来自 ADC 样本或本地数据源）。

`show_data_lite.php`文件由标准 HTML 代码和特殊的 PHP 代码部分组成。HTML 代码将`ACD Data`设置为页面头部的标题，并使用以下命令使页面每 10 秒自动重新加载：

```py
<meta http-equiv="refresh" content="10" > 
```

接下来，我们定义一个`Delete`按钮，当单击时将加载`del_data_lite.php`页面：

```py
<input type="button" onclick="location.href = 'del_data_lite.php';" value="Delete"> 
```

最后，我们使用 PHP 代码部分加载 SQLite 数据库并显示通道 0 数据。

我们使用以下 PHP 命令打开我们之前存储数据的 SQLite 数据库（位于`/var/databases/testsites/mydatabase.db`）：

```py
$db = new PDO("sqlite:/var/databases/testsite/mydatabase.db"); 
```

接下来，我们使用以下 SQLite 查询来选择所有区域包含文本`0:`的条目（例如，`0:Light`）：

```py
SELECT * FROM recordeddatarecordeddata WHERE itm_namename LIKE '%temp%''
```

请注意，即使我们现在使用 PHP，我们与 SQLite 数据库使用的查询与使用`sqlite3` Python 模块时使用的查询相同。

现在我们将查询结果收集在`$response`变量中：

```py
$response = $db->query($strSQL); 
Allowing us to use fetch() (like we used cursor.fetchall() previously) to list all the data columns in each of the data entries within the response. 
while($column = $response->fetch()) 
{ 
   //Display the content of the response 
   echo $column[0] . " "; 
   echo $column[1] . " "; 
   echo $column[2] . " "; 
   echo $column[3] . "<br />"; 
} 
?> 
```

`del_data_lite.php`文件与之前相似；它首先像以前一样重新打开`mydatabase.db`文件。然后执行以下 SQLite 查询：

```py
DROP TABLE recordeddata 
```

如“还有更多...”部分所述，这将从数据库中删除`recordeddata`表。如果`response`不等于 1，则操作未完成。这样做的最有可能原因是包含`mydatabase.db`文件的目录不可写入 Web 服务器（请参阅*如何操作...*部分中关于将文件所有者更改为`www-data`的注意事项）。

最后，我们提供另一个按钮，将用户带回`show_data_lite.php`页面（这将显示已清除记录的数据）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/30098cc2-0e88-427e-bb10-2b8e1445ca72.png)Show_data_lite.php

# 还有更多...

您可能已经注意到，这个教程更多地关注了 HTML 和 PHP，而不是 Python（是的，请检查封面-这仍然是一本面向 Python 程序员的书！）。然而，重要的是要记住，工程的关键部分是集成和组合不同的技术以产生期望的结果。

从设计上讲，Python 非常适合这种任务，因为它允许轻松定制和与大量其他语言和模块集成。我们可以完全在 Python 中完成所有工作，但为什么不利用现有的解决方案呢？毕竟，它们通常有很好的文档，经过了广泛的测试，并且通常符合行业标准。

# 安全性

SQL 数据库在许多地方用于存储各种信息，从产品信息到客户详细信息。在这种情况下，用户可能需要输入信息，然后将其形成为 SQL 查询。在实现不良的系统中，恶意用户可能能够在其响应中包含额外的 SQL 语法，从而允许他们危害 SQL 数据库（也许是访问敏感信息，更改它，或者仅仅删除它）。

例如，在网页中要求用户名时，用户可以输入以下文本：

```py
John; DELETE FROM Orders  
```

如果直接使用这个来构建 SQL 查询，我们最终会得到以下结果：

```py
SELECT * FROM Users WHERE UserName = John; DELETE FROM CurrentOrders  
```

我们刚刚允许攻击者删除`CurrentOrders`表中的所有内容！

使用用户输入来构成 SQL 查询的一部分意味着我们必须小心允许执行哪些命令。在这个例子中，用户可能能够清除潜在重要的信息，这对公司和其声誉可能是非常昂贵的。

这种技术称为 SQL 注入，可以通过使用 SQLite `execute()`函数的参数选项轻松防范。我们可以用更安全的版本替换我们的 Python SQLite 查询，如下所示：

```py
sqlquery = "INSERT INTO %s (itm_name, itm_value) VALUES(?, ?)" %(TABLE) 
cursor.execute(sqlquery, (str(dataName), str(data[i])) 
```

不要盲目地构建 SQL 查询，SQLite 模块将首先检查提供的参数是否是有效的值，然后确保插入命令不会导致额外的 SQL 操作。最后，`dataName`和`data[i]`参数的值将用于替换`?`字符，生成最终安全的 SQLite 查询。

# 使用 MySQL 替代

SQLite 是这个示例中使用的数据库之一，它只是众多可用的 SQL 数据库之一。它对于只需要相对较小的数据库和最少资源的小型项目非常有用。但是，对于需要额外功能（如用户帐户来控制访问和额外安全性）的大型项目，您可以使用其他选择，如 MySQL。

要使用不同的 SQL 数据库，您需要调整我们用来捕获条目的 Python 代码，使用适当的 Python 模块。

对于 MySQL（`mysql-server`），我们可以使用一个名为**PyMySQL**的兼容 Python 3 的库来进行接口。有关如何使用此库的其他信息，请参阅 PyMySQL 网站（[`github.com/PyMySQL/PyMySQL`](https://github.com/PyMySQL/PyMySQL)）。

要在 PHP 中使用 MySQL，您还需要 PHP MySQL（`php5-mysql`）；有关更多信息，请参阅 W3 Schools 的优秀资源（[`www.w3schools.com/php/php_mysql_connect.asp`](http://www.w3schools.com/php/php_mysql_connect.asp)）。

您会注意到，尽管 SQL 实现之间存在细微差异，但无论您选择哪种，一般概念和命令现在应该对您来说都很熟悉。

# 感知和发送数据到在线服务

在本节中，我们将使用一个名为 Xively 的在线服务。该服务允许我们在线连接、传输和查看数据。Xively 使用一种称为**REpresentational State Transfer**（**REST**）的用于在 HTTP 上传输信息的常见协议。REST 被许多服务使用，如 Facebook 和 Twitter，使用各种密钥和访问令牌来确保数据在授权的应用程序和经过验证的站点之间安全传输。

您可以使用名为`requests`的 Python 库手动执行大多数 REST 操作（例如`POST`、`GET`、`SET`等）。

然而，通常更容易使用特定于您打算使用的服务的特定库。它们将处理授权过程并提供访问功能，如果服务发生变化，可以更新库而不是您的代码。

我们将使用`xively-python`库，该库提供了 Python 函数，使我们能够轻松地与该站点进行交互。

有关`xively-python`库的详细信息，请参阅[`xively.github.io/xively-python/`](http://xively.github.io/xively-python/)。

Xively 收集的数据显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/e1e1b35d-5143-4696-94bb-89c7e335ec3d.png)Xively 收集和以 REST 传输的数据绘图

# 准备工作

您需要在[www.xively.com](http://www.xively.com)创建一个帐户，我们将使用该帐户接收我们的数据。转到该网站并注册一个免费的开发者帐户：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/171e04cc-7068-4787-8d92-52d677a2d662.png)注册并创建 Xively 帐户

注册并验证您的帐户后，您可以按照指示进行测试。这将演示如何链接到您的智能手机的数据（陀螺仪数据，位置等），这将让您了解我们可以如何使用树莓派。

当您登录时，您将被带到开发设备仪表板（位于 WebTools 下拉菜单中）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/56379efd-0385-4ae2-84ad-c91271596a48.png)添加新设备

选择+添加设备并填写详细信息，为您的设备命名并将设备设置为私有。

现在您将看到远程设备的控制页面，其中包含您连接设备所需的所有信息，以及您的数据将显示的位置：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/201ad47f-347f-475a-8408-26c5b4b09e9f.png)示例 API 密钥和数据源编号（这将是您的设备的唯一编号）

尽管此页面上有很多信息，但您只需要两个关键信息：

+   API 密钥（在`API Keys`部分中的长代码），如下：

```py
API_KEY = CcRxJbP5TuHp1PiOGVrN2kTGeXVsb6QZRJU236v6PjOdtzze 
```

+   数据源编号（在`API Keys`部分中提到，并在页面顶部列出），如下：

```py
FEED_ID = 399948883 
```

现在我们已经获得了与 Xively 连接所需的详细信息，我们可以专注于树莓派方面的事情。

我们将使用`pip-3.2`来安装 Xively，如下所示：

```py
sudo pip-3.2 install xively-python  
```

确保以下内容已报告：

```py
Successfully installed xively-python requests  
```

您现在可以从您的树莓派发送一些数据了。

# 如何做...

创建以下名为`xivelyLog.py`的脚本。确保您在代码中设置`FEED_ID`和`API_KEY`以匹配您创建的设备：

```py
#!/usr/bin/env python3 
#xivelylog.py 
import xively 
import time 
import datetime 
import requests 
from random import randint 
import data_local as dataDevice 

# Set the FEED_ID and API_KEY from your account 
FEED_ID = 399948883 
API_KEY = "CcRxJbP5TuHp1PiOGVrN2kTGeXVsb6QZRJU236v6PjOdtzze" 
api = xively.XivelyAPIClient(API_KEY) # initialize api client 
DEBUG=True 

myData = dataDevice.device() 
myDataNames=myData.getName() 

def get_datastream(feed,name,tags): 
  try: 
    datastream = feed.datastreams.get(name) 
    if DEBUG:print ("Found existing datastream") 
    return datastream 
  except: 
    if DEBUG:print ("Creating new datastream") 
    datastream = feed.datastreams.create(name, tags=tags) 
    return datastream 

def run(): 
  print ("Connecting to Xively") 
  feed = api.feeds.get(FEED_ID) 
  if DEBUG:print ("Got feed" + str(feed)) 
  datastreams=[] 
  for dataName in myDataNames: 
    dstream = get_datastream(feed,dataName,dataName) 
    if DEBUG:print ("Got %s datastream:%s"%(dataName,dstream)) 
    datastreams.append(dstream) 

  while True: 
    data=myData.getNew() 
    for idx,dataValue in enumerate(data): 
      if DEBUG: 
        print ("Updating %s: %s" % (dataName,dataValue)) 
      datastreams[idx].current_value = dataValue 
      datastreams[idx].at = datetime.datetime.utcnow() 
    try: 
      for ds in datastreams: 
        ds.update() 
    except requests.HTTPError as e: 
      print ("HTTPError({0}): {1}".format(e.errno, e.strerror)) 
    time.sleep(60) 

run() 
#End 
```

# 它是如何工作的...

首先，我们初始化 Xively API 客户端，为其提供`API_KEY`（这将授权我们向我们之前创建的`Xively`设备发送数据）。接下来，我们使用`FEED_ID`将我们链接到我们要发送数据的特定数据源。最后，我们请求数据流连接（如果在数据源中不存在，`get_datastream()`函数将为我们创建一个）。

对于数据源中的每个数据流，我们提供一个`name`函数和`tags`（这些是帮助我们识别数据的关键字；我们可以使用我们的数据名称）。

一旦我们定义了我们的数据流，我们就进入`main`循环。在这里，我们从`dataDevice`中收集我们的数据值。然后，我们设置`current_value`函数和每个数据项的时间戳，并将它们应用于我们的数据流对象。

最后，当所有数据准备就绪时，我们更新每个数据流，并将数据发送到 Xively，在设备的仪表板上几秒钟内显示出来。

我们可以登录到我们的 Xively 帐户并查看数据，使用标准的网络浏览器。这提供了发送数据和在世界各地远程监视数据的手段（如果需要，甚至可以同时从几个树莓派发送数据）。该服务甚至支持创建触发器，如果某些项目超出预期范围，达到特定值或符合设定标准，则可以发送额外的消息。触发器反过来可以用于控制其他设备或引发警报等。它们还可以用于其他平台，如 ThingSpeak 或 plot.ly。

# 另请参阅

AirPi 空气质量和天气项目（[`airpi.es`](http://airpi.es)）向您展示如何添加自己的传感器或使用他们的 AirPi 套件创建自己的空气质量和天气站（并将数据记录到您自己的 Xively 帐户）。该网站还允许您与世界各地的其他人分享您的 Xively 数据源。
