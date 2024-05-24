# JavaScript 物联网实战（一）

> 原文：[`zh.annas-archive.org/md5/8F10460F1A267E7E0720699DAEDCAC44`](https://zh.annas-archive.org/md5/8F10460F1A267E7E0720699DAEDCAC44)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

我们处于一个人们已经开始适应物联网产品的时代。物联网引起了很大的热情。本书将专注于构建基于物联网的应用程序，这将帮助您在物联网方面达到更高的理解水平。它将采用基于项目的方法，教会您构建独立的令人兴奋的应用程序，并教会您将项目扩展到另一个水平。我们将使用 JavaScript 作为我们的编程语言，Raspberry Pi 3 作为我们的硬件来构建有趣的物联网解决方案。

# 本书涵盖的内容

第一章，*物联网的世界*，向您介绍了物联网的世界。我们将回顾物联网的历史，确定一些用例，并对本书将涵盖的技术进行技术概述。

第二章，*IoTFW.js - I*，向您介绍了如何使用 JavaScript 构建物联网解决方案的参考框架。在本章中，我们将介绍高级架构，并开始安装所需的软件。我们将从下载基本应用程序开始，并将树莓派与 MQTTS 代理和 API 引擎连接在一起。

第三章，*IoTFW.js - II*，从上一章结束的地方继续，并完成了 API 引擎、Web 应用程序、桌面应用程序和移动应用程序的实现。在本章末尾，我们将使用 LED 和温度传感器实现一个简单的示例，应用程序的指令将打开/关闭 LED，并且温度传感器的数值将实时更新。

第四章，*智能农业*，讨论了使用我们构建的参考架构来构建一个简单的气象站。气象站由四个传感器组成，使用这些传感器我们可以监测农场条件。我们将对 API 引擎、Web 应用程序、桌面应用程序和移动应用程序进行必要的更改。

第五章，*智能农业和语音 AI*，展示了我们如何利用语音 AI 技术来构建有趣的物联网解决方案。我们将与智能气象站一起工作，并向该设置添加一个单通道机械继电器。然后，使用语音命令和亚马逊 Alexa，我们将管理气象站。

第六章，*智能可穿戴设备*，讨论了医疗保健领域中一个有趣的用例，术后患者护理。使用配有简单加速度计的智能可穿戴设备，可以轻松检测患者是否摔倒。在本章中，我们构建了所需的设置来收集传感器的加速度计值。

第七章，*智能可穿戴设备和 IFTTT*，解释了从加速度计收集的数据如何用于检测摔倒，并同时通知 API 引擎。使用一个名为**If This Then That**（**IFTTT**）的流行概念，我们将构建自己的规则引擎，根据预定义的规则采取行动。在我们的示例中，如果检测到摔倒，我们将向患者的照料者发送电子邮件。

第八章，*树莓派图像流*，展示了如何利用树莓派摄像头模块构建实时图像流（MJPEG 技术）解决方案，以监视您的周围环境。我们还将实现基于运动的视频捕获，以在检测到运动时捕获视频。

第九章，*智能监控*，将带您了解如何使用亚马逊的 Rekognition 平台进行图像识别。我们将在检测到运动时使用树莓派 3 相机模块捕获图像。然后，我们将把这张图片发送到亚马逊的 Rekognition 平台，以便检测我们拍摄的图片是入侵者还是我们认识的人。

# 本书所需内容

要开始使用 JavaScript 构建物联网解决方案，您需要具备以下知识：

+   JavaScript 的中级到高级知识-ES5 和 ES6

+   MEAN 堆栈应用程序开发的中级到高级知识

+   Angular 4 的中级到高级知识

+   Electron Framework 的中级到高级知识

+   Ionic Framework 3 的中级到高级知识

+   数字电子电路的初级到中级知识

+   树莓派的初级到中级知识

+   传感器和执行器的初级到中级知识

# 本书适合对象

本书适合那些已经精通 JavaScript 并希望将其 JavaScript 知识扩展到物联网领域的读者。对于有兴趣创建令人兴奋的项目的物联网爱好者，本书也会很有用。本书还适合那些擅长使用树莓派开发独立解决方案的读者；本书将帮助他们利用世界上最被误解的编程语言为其现有项目添加物联网功能。

# 约定

在本书中，您会发现一些不同种类信息的文本样式。以下是一些这些样式的示例和它们的含义解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名会以以下形式显示：“现在，在`broker`文件夹内，创建另一个名为`certs`的文件夹，并`cd`进入该文件夹。”代码块设置如下：

```js
// MongoDB connection options
    mongo: {
        uri: 'mongodb://admin:admin123@ds241055.mlab.com:41055/iotfwjs'
    },

    mqtt: {
        host: process.env.EMQTT_HOST || '127.0.0.1',
        clientId: 'API_Server_Dev',
        port: 8883
    }
};
```

任何命令行输入或输出都以以下形式书写：

```js
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem 
```

**新术语**和**重要词汇**以粗体显示。您在屏幕上看到的词语，例如菜单或对话框中的词语，会以这样的形式出现在文本中：“登录后，点击“创建新”按钮来创建一个新的数据库。”

警告或重要提示会出现在这样的形式。提示和技巧会以这种形式出现。


# 第一章：物联网的世界

欢迎来到使用 JavaScript 的高级物联网。在本书中，我们将探讨使用 JavaScript 作为编程语言构建物联网解决方案。在我们开始技术深入之前，我想谈谈物联网的世界，它提供的解决方案，以及我们作为开发人员所承担的责任。在本章中，我们将讨论以下主题：

+   物联网的世界

+   物联网的历史

+   物联网使用案例

+   技术概述

+   产品工程

# 物联网的世界

想象一种情景，你的牛奶用完了；你注意到了并把它放在了购物清单上。但由于不可预见的原因，你忘了买牛奶；嗯，第二天你就没有牛奶了。

现在想象另一种情景：你有一个智能冰箱，它注意到你的牛奶快用完了，把牛奶放在你的购物清单上，然后更新你的 GPS 路线，让你经过超市回家，但你还是忘了。

现在你必须面对你的冰箱的愤怒。

现在事情变得真实起来，想象另一种情况，你的冰箱跳过了中间商，直接在亚马逊上下订单，亚马逊在你第二天早餐需要的时候送货。

第三种情景是我们追求的。让一台机器与另一台机器交流并做出相应决策；在购买之前自动验证牛奶的类型、数量和过期日期等事项。

我们人类现在正在利用连接设备和智能设备的世界来让我们的生活变得更好。

# 什么是物联网？

如果你至少呼吸了十年，你一定听过智能生活、智能空间和智能设备等术语。所有这些都指的是一个称为**物联网**（**IoT**）的父概念。

简而言之，当我们的电子、电气或电机械设备连接到互联网并相互交流时，就是物联网。

智能设备主要围绕两件事展开：

+   传感器

+   执行器

物联网领域的任何解决方案都是要么感知某物，要么执行某事。

有了这项技术，我们为谢尔顿·库珀（来自 CBS 电视系列剧《生活大爆炸》）找到了解决方案，他想知道有人坐在他的位置上时立刻得知：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00005.jpeg)来源：http://bigbangtheory.wikia.com/wiki/Sheldon%27s_Spot

我们所做的就是在沙发下放一个重量传感器，如果重量增加，传感器将触发指向沙发的摄像头拍照并发送一张照片的推送通知给他。怎么样？

我知道我举的例子有点过分，但你明白我的意思，对吧？

# 一点历史

物联网以各种形式存在已有 35 年以上。我找到的最早的例子是 1982 年在卡内基梅隆大学的一台可乐机。由四名研究生迈克·卡扎尔、大卫·尼科尔斯、约翰·扎尔纳伊和艾沃尔·德勒姆开发，他们将可乐机连接到互联网，这样他们就可以从自己的办公桌上检查机器里是否装满了冷可乐。来源（[`www.cs.cmu.edu/~coke/`](https://www.cs.cmu.edu/~coke/)）。

蒂莫西·约翰·伯纳斯-李爵士于 1991 年发明了第一个网页。

另一个例子是约翰·罗姆基的互联网烤面包机。他使用 TCP/IP 协议将他的烤面包机连接到互联网。他创建了一个控制来打开烤面包机，一个控制来关闭它。当然，有人必须把面包放进烤面包机：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00006.jpeg)来源：http://ieeexplore.ieee.org/document/7786805/

另一个有趣的物联网例子是特洛伊房间咖啡壶。这是由昆汀·斯塔福德-弗雷泽和保罗·贾德茨基于 1993 年创建的。一台摄像机位于剑桥大学计算机实验室的特洛伊房间，监视着咖啡壶的水平，每分钟更新一次图像并发送到建筑的服务器：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00007.jpeg)来源：https://en.wikipedia.org/wiki/Trojan_Room_coffee_pot

正如之前提到的，我们可以看到，甚至在我们能够想象到可能性之前，人们已经在互联网相关的解决方案上进行了工作。

在过去的两年里，有一件事情让我一直看到并开始坚信：

“懒惰是发明之母。”

不是必要性，也不是无聊，而是懒惰。在当今时代，没有人想做像购物、走到开关旁边打开灯或空调这样的日常事务。因此，我们正在寻找解决这些问题的新颖创新的方法。

# 物联网用例

现在您对物联网有了一定的了解，您可以想象使用这种技术可以构建的无限可能性。

根据我的观察，物联网用例可以粗略地分为三个部分：

+   解决问题

+   便利

+   炫耀

问题解决部分涉及物联网用于解决现实世界问题，例如，一个农民的农场距离家有半公里，他们必须一直走到农场才能打开水泵/发动机。另一个场景是术后患者出院后可以定期将其生命体征发送到医院，以监测患者是否有任何异常。这正是物联网非常适合的地方。

便利是指您可以在到达家之前 30 分钟打开空调，这样您进入时就可以放松，或者在工作时解锁您的门，如果您认识的人敲门而您不在附近。

炫耀是指您去另一个国家只是为了打开或关闭门廊灯，只是为了展示物联网的工作。

所有这些都是对这种技术的消费形式。

在本书中，我们将探讨一些属于先前用例的解决方案。

# 技术概述

现在我们知道了什么是物联网，我们可以开始定义技术堆栈。在本书中，我们将使用 JavaScript 构建一个通用框架，用于开发物联网应用程序。

我们将遵循云计算的方法，其中有一堆连接到云的设备，与雾计算方法相比，后者有一个网关，几乎可以做云可以做的所有事情，但是在本地可用于现场。

我们的智能设备将由树莓派 3 供电，它具有通过 Wi-Fi 与云进行通信的能力，并且可以使用其 GPIO 引脚与传感器和执行器进行通信。使用这个简单的硬件，我们将在本书中连接传感器和执行器，并构建一些真实世界的解决方案。

另一个替代品是树莓派 Zero W，这是树莓派 3 的微型版本，如果您想构建一个紧凑的解决方案。

我们将在第二章 *IoTFW.js - I*和第三章 *IoTFW.js - II*中逐步介绍每一种技术，并从那里开始使用这些技术在各个领域构建物联网解决方案。

# 产品工程

与软件开发不同，硬件开发确实很难。所花费的时间、复杂性和执行都很昂贵。想象一下 JavaScript 控制台中的语法错误；我们只需要转到特定的行号，进行更改，然后刷新浏览器。

现在将这与硬件产品开发进行比较。从确定一件硬件产品到将其作为收缩包装产品放在超市货架上，至少需要 8 个月的时间，至少需要制作四个产品迭代，以验证并在现实世界中测试它。

举个例子，产品上的组件定位会使产品成功或失败。想象一下如果充电器插头上没有凸起或握把；您在从插座中拔出充电器时手会一直滑动。这就是价值工程。

组建一个**概念验证**（**POC**）非常简单，正如您将在本书的其余部分中看到的那样。将这个 POC 转变成一个成品产品是完全不同的事情。这种区别就像在你的浴室里唱歌和在有数百万观众的舞台上唱歌一样。

请记住，我们在本书中构建的示例都是 POC，并且没有一个远远接近用于产品生产。您可以始终使用我们在本书中将要研究的解决方案来更好地理解实施，然后围绕它们设计自己的解决方案。

# 总结

在本章中，我们看了一下什么是物联网以及一些相关历史。接下来，我们看了一些用例，一个高层次的技术概述，以及一些关于产品工程的内容。

在第二章中，*IoTFW.js - I*，我们将开始构建物联网框架，我们将在其上构建我们的解决方案。


# 第二章：IoTFW.js - I

在本章和第三章，*IoTFW.js - II*中，我们将开发一个用于构建各种物联网解决方案的参考架构。该参考架构或物联网框架将作为我们未来在本书中要开发的物联网解决方案的基础。我们将称这个参考架构或框架为 IoTFW.js。我们将致力于以下主题，以使 IoTFW.js 生动起来：

+   设计 IoTFW.js 架构

+   开发基于 Node.js 的服务器端层

+   开发一个基于 Angular 4 的 Web 应用程序

+   开发一个基于 Ionic 3 的移动应用程序

+   开发一个基于 Angular 4 和 Electron.js 的桌面应用程序

+   在树莓派 3 上设置和安装所需的依赖关系

+   整合所有的部分

我们将在本章中涵盖一些先前的主题，以及第三章，*IoTFW.js - II*中的一些主题。

# 设计一个参考架构

正如我们在第一章，*物联网的世界*中所看到的，我们将要处理的所有示例都有一个共同的设置。那就是硬件、固件（在硬件上运行的软件）、代理、API 引擎和用户应用程序。

我们将在遇到相关框架的部分时进行扩展。

在需要时，我们将扩展硬件、移动应用程序或 API 引擎。

通过这个参考架构，我们将在现实世界中的设备与虚拟世界中的云之间建立一个管道。换句话说，物联网是设备和互联网之间的最后一英里解决方案。

# 架构

使用树莓派、Wi-Fi 网关、云引擎和用户界面应用程序组合在一起的简单参考架构如下图所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00008.jpeg)

在非常高的层面上，我们在左侧有智能设备，在右侧有用户设备。它们之间的所有通信都通过云端进行。

以下是先前架构中每个关键实体的描述。我们将从左侧开始，向右移动。

# 智能设备

智能设备是硬件实体，包括传感器、执行器或两者，任何微控制器或微处理器，在我们的案例中是树莓派 3。

传感器是一种可以感知或测量物理特性并将其传回微控制器或微处理器的电子元件。传回的数据可以是周期性的或事件驱动的；事件驱动的意思是只有在数据发生变化时才会传回。温度传感器，如 LM35 或 DHT11，就是传感器的一个例子。

执行器也是可以触发现实世界中动作的电机械组件。通常，执行器不会自行行动。微控制器、微处理器或电子逻辑发送信号给执行器。执行器的一个例子是机械继电器。

我们在本书中提到的微处理器将是树莓派 3。

树莓派 3 是由树莓派基金会设计和开发的单板计算机。树莓派 3 是第三代树莓派。

在本书中，我们将使用树莓派 3 型 B 来进行所有示例。树莓派 3 型 B 的一些规格如下：

| **特性** | **规格** |
| --- | --- |
| 代 | 3 |
| 发布日期 | 2016 年 2 月 |
| 架构 | ARMv8-A（64/32 位） |
| 系统芯片（SoC） | Broadcom BCM2837 |
| CPU | 1.2 GHz 64 位四核 ARM Cortex-A53 |
| 内存（SDRAM） | 1 GB（与 GPU 共享） |
| USB 2.0 端口 | 4（通过机载 5 端口 USB 集线器） |
| 机载网络 | 10/100 兆比特/秒以太网，802.11n 无线，蓝牙 4.1 |
| 低级外围设备 | 17× GPIO 加上相同的特定功能，和 HAT ID 总线 |
| 功率评级 | 空闲时平均 300 毫安（1.5 瓦），在压力下最大 1.34 安（6.7 瓦）（监视器、键盘、鼠标和 Wi-Fi 连接） |
| 电源 | 通过 MicroUSB 或 GPIO 引脚的 5V |

有关规格的更多信息，请参考树莓派的规格：[`en.wikipedia.org/wiki/Raspberry_Pi#Specifications`](https://en.wikipedia.org/wiki/Raspberry_Pi#Specifications)。

# 网关

我们架构中的下一个部分是 Wi-Fi 路由器。一个普通的家用 Wi-Fi 路由器将作为我们的网关。正如我们在第一章中所看到的，在*物联网的世界*中，*集群设备与独立设备*部分，我们遵循独立设备的方法，其中每个设备都是自给自足的，并且有自己的无线电与外界通信。我们将要构建的所有项目都包括一个树莓派 3，它具有微处理器以及与传感器和执行器进行通信的无线电。

# MQTTS 代理

我们参考框架中的下一个重要部分是设备和云之间的安全通信通道。我们将使用 MQTT 作为我们的通信通道。MQTT 在以下引用中描述：[`mqtt.org/faq`](http://mqtt.org/faq)。

MQTT 代表 MQ 遥测传输。这是一种发布/订阅、非常简单和轻量级的消息传递协议，设计用于受限设备和低带宽、高延迟或不可靠网络。设计原则是尽量减少网络带宽和设备资源需求，同时也尝试确保可靠性和一定程度的传递保证。

我们将使用 MQTT over SSL 或 MQTTS。在我们的架构中，我们将使用 Mosca（[`www.mosca.io/`](http://www.mosca.io/)）作为我们的 MQTTS 代理。Mosca 是一个 Node.js MQTT 代理。当我们开始使用它时，我们将更多地谈论 Mosca。

# API 引擎

API 引擎是一个基于 Node.js、Express 编写的 Web 服务器应用，具有 MongoDB 作为持久化层。该引擎负责与 Mosca 通信作为 MQTT 客户端，将数据持久化到 MongoDB，并使用 Express 公开 API。然后应用程序使用这些 API 来显示数据。

我们还将实现基于套接字的 API，用于用户界面在设备和服务器之间实时获取通知。

# MongoDB

我们将使用 MongoDB 作为我们的数据持久化层。MongoDB 是一个 NoSQL 文档数据库，允许我们在一个集合中保存具有不同模式的文档。这种数据库非常适合处理来自各种设备的传感器数据，因为数据结构或参数因解决方案而异。要了解有关 MongoDB 的更多信息，请参阅[`www.mongodb.com/`](https://www.mongodb.com/)。

# Web 应用

Web 应用是一个简单的 Web/移动 Web 界面，将实现 API 引擎公开的 API。这些 API 将包括身份验证，访问特定的智能设备，获取智能设备的最新数据，并通过 API 将数据发送回智能设备。我们将使用 Angular 4（[`angular.io/`](https://angular.io/)）和 Twitter Bootstrap 3（[`getbootstrap.com/`](http://getbootstrap.com/)）技术来构建 Web 应用。

# 移动应用

我们将采用混合移动方法来构建我们的移动应用。移动应用实现了 API 引擎公开的 API。这些 API 将包括身份验证，访问特定的智能设备，获取智能设备的最新数据，并通过 API 将数据发送回智能设备。我们将使用 Ionic 3（[`ionicframework.com/`](http://ionicframework.com/)），它由 Angular 4 提供支持，来构建移动应用。

# 桌面应用

我们将采用桌面混合方法来构建我们的桌面应用程序。桌面应用程序将实现 API 引擎提供的 API。这些 API 将包括身份验证，访问特定的智能设备，从智能设备获取最新数据，并通过 API 将数据发送回智能设备。我们将使用 Electron ([`electron.atom.io/`](https://electron.atom.io/))作为构建桌面应用程序的外壳。我们将使用 Angular 4 和 Twitter Bootstrap 3 ([`getbootstrap.com/`](http://getbootstrap.com/))技术来构建桌面应用程序。我们会尽量在 Web 和桌面应用程序之间重用尽可能多的代码。

# 数据流

现在我们了解了架构的各个部分，我们现在将看一下组件之间的数据流。我们将讨论从智能设备到应用程序以及反之的数据流。

# 智能设备到应用程序

从传感器到用户设备的简单数据流程如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00009.jpeg)

从上图可以看出，数据源自传感器；树莓派 3 读取这些数据，并通过 Wi-Fi 路由器将数据发布到 MQTTS 代理（Mosca）。一旦代理接收到数据，它将把数据发送到 API 引擎，API 引擎将数据持久化到数据库中。数据成功保存后，API 引擎将把新数据发送到我们的应用程序，以实时显示数据。

这里需要注意的一点是，API 引擎将充当 MQTT 客户端，并订阅设备发布数据的主题。我们将在实施时查看这些主题。

一般来说，在这种流程中的数据将是典型的传感器传输数据。

# 应用程序到智能设备

以下图表显示了数据如何从应用程序流向智能设备：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00010.jpeg)

从上图可以看出，如果应用程序希望向智能设备发送指令，它会将该消息发送到 API 引擎。然后 API 引擎将数据持久化到数据库，并将数据发布到 MQTTS 代理，以传递给设备。设备将根据这些数据做出反应。

请注意，在这两种流程中，MQTTS 代理管理设备，API 引擎管理应用程序。

# 构建参考架构

在本节中，我们将开始组合所有部件并组合所需的设置。我们将从 Node.js 安装开始，然后是数据库，之后，继续其他部件。

# 在服务器上安装 Node.js

在继续开发之前，我们需要在服务器上安装 Node.js。这里的服务器可以是您自己的台式机、笔记本电脑、AWS 机器，或者是一个可能具有或不具有公共 IP 的 digitalocean 实例（[`www.iplocation.net/public-vs-private-ip-address`](https://www.iplocation.net/public-vs-private-ip-address)）。

安装 Node.js，转到[`nodejs.org/en/`](https://nodejs.org/en/)并下载适合您的机器的版本。安装完成后，您可以通过从命令提示符/终端运行以下命令来测试安装：

```js
node -v
# v6.10.1
```

和

```js
npm -v
# 3.10.10  
```

您可能拥有比之前显示的版本更新的版本。

现在我们有了所需的软件，我们将继续。

# 安装 nodemon

现在我们已经安装了 Node.js，我们将安装 nodemon。这将负责自动重新启动我们的节点应用程序。运行：

```js
npm install -g nodemon
```

# MongoDB

您可以按照以下列出的两种方式之一设置数据库。

# 本地安装

我们可以在服务器上设置 MongoDB 作为独立安装。这样，数据库就在服务器上运行，并且数据会持久保存在那里。

根据您的操作系统，您可以按照提供的说明在[`docs.mongodb.com/manual/installation/`](https://docs.mongodb.com/manual/installation/)上设置数据库。

安装完数据库后，为了测试一切是否正常工作，您可以打开一个新的终端，并通过运行以下命令启动 Mongo 守护进程：

```js
mongod  
```

您应该看到类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00011.jpeg)

我正在使用默认端口`27017`运行数据库。

现在我们将使用 mongo shell 与数据库进行交互。打开一个新的命令提示符/终端，并运行以下命令：

```js
mongo  
```

这将带我们进入`mongo` shell，通过它我们可以与 MongoDB 进行交互。以下是一些方便的命令：

| **描述** | **命令** |
| --- | --- |
| 显示所有数据库 | `show dbs` |
| 使用特定数据库 | `use local` |
| 创建数据库 | `use testdb` |
| 检查正在使用的数据库 | `db` |
| 创建集合 | `db.createCollection("user");` |
| 显示数据库中的所有集合 | `show collections` |
| （创建）在集合中插入文档 | `db.user.insert({"name":"arvind"});` |
| （读取）查询集合 | `db.user.find({});` |
| （更新）修改集合中的文档 | `db.user.update({"name": "arvind"}, {"name" : "arvind2"}, {"upsert":true});` |
| （删除）删除文档 | `db.user.remove({"name": "arvind2"});` |

使用前面的命令，您可以熟悉 Mongo shell。在我们的 API 引擎中，我们将使用 Mongoose ODM（[`mongoosejs.com/`](http://mongoosejs.com/)）来管理 Node.js/Express--API 引擎。

# 使用 mLab

如果您不想费心在本地设置数据库，可以使用 mLab（[`mlab.com/`](https://mlab.com/)）等 MongoDB 作为服务。在本书中，我将遵循这种方法。我将使用 mLab 的实例，而不是本地数据库。

要设置 mLab MongoDB 实例，首先转到[`mlab.com/login/`](https://mlab.com/login/)并登录。如果您没有帐户，可以通过转到[`mlab.com/signup/`](https://mlab.com/signup/)来创建一个。

mLab 有一个免费的层，我们将利用它来构建我们的参考架构。免费层非常适合像我们这样的开发和原型项目。一旦我们完成了实际的开发，并且准备好生产级应用程序，我们可以考虑一些更可靠的计划。您可以在[`mlab.com/plans/pricing/`](https://mlab.com/plans/pricing/)上了解定价。

一旦您登录，单击“创建新”按钮以创建新的数据库。现在，在云提供商下选择亚马逊网络服务，然后选择计划类型为 FREE，如下图所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00012.jpeg)

最后，将数据库命名为`iotfwjs`，然后单击“创建”。然后，几秒钟后，我们应该为我们创建一个新的 MongoDB 实例。

一旦数据库创建完成，打开`iotfwjs`数据库。我们应该看到一些警告：一个是指出这个沙箱数据库不应该用于生产，我们知道这一点，另一个是没有数据库用户存在。

所以，让我们继续创建一个。单击“用户”选项卡，然后单击“添加数据库用户”按钮，并使用用户名`admin`和密码`admin123`填写表单，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00013.jpeg)

您可以选择自己的用户名和密码，并相应地在本书的其余部分进行更新。

现在来测试连接到我们的数据库，使用页面顶部的部分使用`mongo` shell 进行连接。在我的情况下，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00014.jpeg)

打开一个新的命令提示符，并运行以下命令（在相应地更新 mLab URL 和凭据之后）：

```js
mongo ds241055.mlab.com:41055/iotfwjs -u admin -p admin123  
```

我们应该能够登录到 shell，并可以从这里运行查询，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00015.jpeg)

这完成了我们的 MongoDB 设置。

# MQTTS 代理 - Mosca

在本节中，我们将组装 MQTTS 代理。我们将使用 Mosca ([`www.mosca.io/`](http://www.mosca.io/))作为独立服务 ([`github.com/mcollina/mosca/wiki/Mosca-as-a-standalone-service`](https://github.com/mcollina/mosca/wiki/Mosca-as-a-standalone-service))。

创建一个名为`chapter2`的新文件夹。在`chapter2`文件夹内，创建一个名为`broker`的新文件夹，并在该文件夹内打开一个新的命令提示符/终端。然后运行以下命令：

```js
npm install mosca pino -g  
```

这将全局安装 Mosca 和 Pino。Pino ([`github.com/pinojs/pino`](https://github.com/pinojs/pino))是一个 Node.js 日志记录器，它记录 Mosca 抛出的所有消息到控制台。

现在，Mosca 的默认版本实现了 MQTT。但我们希望在智能设备和云之间保护我们的通信，以避免中间人攻击。

因此，为了设置 MQTTS，我们需要 SSL 密钥和 SSL 证书。为了在本地创建 SSL 密钥和证书，我们将使用`openssl`。

要检查您的计算机上是否存在`openssl`，运行`openssl version -a`，您应该看到关于您的`openssl`本地安装的信息。

如果您没有`openssl`，您可以从[`www.openssl.org/source/`](https://www.openssl.org/source/)下载。

现在，在`broker`文件夹内，创建一个名为`certs`的文件夹，并`cd`进入该文件夹。运行以下命令生成所需的密钥和证书文件：

```js
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem  
```

这将提示一些问题，您可以按照以下方式填写相同的内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00016.jpeg)

这将在`certs`文件夹内创建两个名为`key.pem`和`certificate.pem`的新文件。我们将在我们的 Mosca 设置中使用这些文件。

接下来，在`broker`文件夹的根目录下，创建一个名为`index.js`的新文件，并按以下方式更新它：

```js
let SSL_KEY = __dirname + '/certs/key.pem';
let SSL_CERT = __dirname + '/certs/certificate.pem';
let MONGOURL = 'mongodb://admin:admin123@ds241055.mlab.com:41055/iotfwjs';

module.exports = {
    id: 'broker',
    stats: false,
    port: 8443,
    logger: {
        name: 'iotfwjs',
        level: 'debug'
    },
    secure: {
        keyPath: SSL_KEY,
        certPath: SSL_CERT,
    },
    backend: {
        type: 'mongodb',
        url: MONGOURL
    },
    persistence: {
        factory: 'mongo',
        url: MONGOURL
    }
};
```

前面的代码是我们将用于启动 Mosca 的配置。此配置加载 SSL 证书和密钥，并将 Mongo 设置为我们的持久层。

保存`index.js`，然后返回到终端/提示符，并`cd`到我们有`index.js`文件的位置。接下来，运行以下命令：

```js
mosca -c index.js -v | pino  
```

我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00017.jpeg)

正如您从前面看到的，我们连接到`iotfwjs`数据库，代理将监听端口`8883`以进行连接。

这完成了我们使用 Mosca 设置 MQTTS 代理的设置。

在下一步中，我们将实现 API 引擎，此时我们将测试 MQTTS 代理与 API 引擎的集成。

# API 引擎 - Node.js 和 Express

在本节中，我们将构建 API 引擎。该引擎与我们的应用程序进行交互，并将智能设备的信息从和到代理进行级联连接。

要开始，我们将克隆一个使用 Yeoman ([`yeoman.io/`](http://yeoman.io/))生成器创建的存储库，名为`generator-node-express-mongo` ([`www.npmjs.com/package/generator-node-express-mongo`](https://www.npmjs.com/package/generator-node-express-mongo))。我们已经使用`generator-node-express-mongo`生成的代码并根据我们的需求进行了修改。

在您的计算机上的某个位置，使用以下命令下载本书的完整代码库：

```js
git clone https://github.com/PacktPublishing/Practical-Internet-of-Things-with-JavaScript.git
```

或者，您也可以从[`github.com/PacktPublishing/Practical-Internet-of-Things-with-JavaScript`](https://github.com/PacktPublishing/Practical-Internet-of-Things-with-JavaScript)下载 zip 文件。

一旦存储库被下载，`cd`进入`base`文件夹，并将`api-engine-base`文件夹复制到`chapter2`文件夹中。

这将下载`api-engine`样板代码。一旦`repo`被克隆，`cd`进入文件夹并运行以下命令：

```js
npm install  
```

这将安装所需的依赖项。

如果我们打开`cloned`文件夹，我们应该看到以下内容：

```js
.
├── package.json
└── server
    ├── api
    │ └── user
    │ ├── index.js
    │ ├── user.controller.js
    │ ├── user.model.js
    ├── app.js
    ├── auth
    │ ├── auth.service.js
    │ ├── index.js
    │ └── local
    │ ├── index.js
    │ └── passport.js
    ├── config
    │ ├── environment
    │ │ ├── development.js
    │ │ ├── index.js
    │ │ ├── production.js
    │ │ └── test.js
    │ ├── express.js
    │ └── socketio.js
    ├── mqtt
    │ └── index.js
    └── routes.js
```

该文件夹包含我们启动 API 引擎所需的所有基本内容。

从前面的结构中可以看出，我们在文件夹的根目录中有一个`package.json`。这个文件包含了所有需要的依赖项。我们还在这里定义了我们的启动脚本。

我们的所有应用程序文件都位于`server`文件夹中。一切都始于`api-engine/server/app.js`。我们初始化`mongoose`、`express`、`socketio`、`config`、`routes`和`mqtt`。最后，我们启动服务器，并在`localhost`的`9000`端口上侦听，借助`server.listen()`。

`api-engine/server/config/express.js`具有初始化 Express 中间件所需的设置。`api-engine/server/config/socketio.js`包含管理 Web 套接字所需的逻辑。

我们将使用`api-engine/server/config/environment`来配置环境变量。在大部分的书中，我们将使用开发环境。如果我们打开`api-engine/server/config/environment/development.js`，我们应该看到`mongo`和`mqtt`的配置。更新它们如下：

```js
// MongoDB connection options
    mongo: {
        uri: 'mongodb://admin:admin123@ds241055.mlab.com:41055/iotfwjs'
    },

    mqtt: {
        host: process.env.EMQTT_HOST || '127.0.0.1',
        clientId: 'API_Server_Dev',
        port: 8883
    }
};
```

根据您的设置更新 mongo URL（mLab 或本地）。由于我们将连接到在本地计算机上运行的 Mosca 代理，我们使用`127.0.0.1`作为主机。

# 授权

接下来，我们将看看开箱即用的身份验证。我们将使用**JSON Web Tokens**（**JWTs**）来验证要与我们的 API 引擎通信的客户端。我们将使用 Passport（[`passportjs.org/`](http://passportjs.org/)）进行身份验证。

打开`api-engine/server/auth/index.js`，我们应该看到使用`require('./local/passport').setup(User, config);`设置护照，并且我们正在创建一个新的身份验证路由。

路由在`api-engine/server/routes.js`中配置。如果我们打开`api-engine/server/routes.js`，我们应该看到`app.use('/auth', require('./auth'));`。这将创建一个名为`/auth`的新端点，在`api-engine/server/auth/index.js`中，我们已经添加了`router.use('/local', require('./local'));`现在，如果我们想要访问`api-engine/server/auth/local/index.js`中的`POST`方法，我们将向`/auth/local`发出 HTTP `POST`请求。

在`api-engine`中，我们使用护照本地认证策略（[`github.com/jaredhanson/passport-local`](https://github.com/jaredhanson/passport-local)）来使用 MongoDB 进行持久化验证用户。

要创建新用户，我们将使用用户 API。如果我们打开`api-engine/server/routes.js`，我们应该看到定义了一个路由来访问用户集合`app.use('/api/v1/users', require('./api/user'));`。我们已经添加了`/api/v1/users`前缀，以便稍后可以对我们的 API 层进行版本控制。

如果我们打开`api-engine/server/api/user/index.js`，我们应该看到定义了以下六个路由：

+   `router.get('/', auth.hasRole('admin'), controller.index);`

+   `router.delete('/:id', auth.hasRole('admin'), controller.destroy);`

+   `router.get('/me', auth.isAuthenticated(), controller.me);`

+   `router.put('/:id/password', auth.isAuthenticated(), controller.changePassword);`

+   `router.get('/:id', auth.isAuthenticated(), controller.show);`

+   `router.post('/', controller.create);`

第一个路由是用于获取数据库中所有用户的路由，并使用`api-engine/server/auth/auth.service.js`中定义的`auth.hasRole`中间件，我们将检查用户是否经过身份验证并具有管理员角色。

下一步是删除具有 ID 的用户的路由；之后，我们有一个根据令牌获取用户信息的路由。我们有一个`PUT`路由来更新用户的信息；一个`GET`路由根据用户 ID 获取用户的信息；最后，一个`POST`路由来创建用户。请注意，`POST`路由没有任何身份验证或授权中间件，因为访问此端点的用户将是第一次使用我们的应用程序（或者正在尝试注册）。

使用`POST`路由，我们将创建一个新用户；这就是我们注册用户的方式：`api-engine/server/api/user/user.model.js`包含了用户的 Mongoose 模式，`api-engine/server/api/user/user.controller.js`包含了我们定义的路由的逻辑。

# MQTT 客户端

最后，我们将看一下 MQTT 客户端与我们的`api-engine`的集成。如果我们打开`api-engine/server/mqtt/index.js`，我们应该会看到 MQTTS 客户端的默认设置。

我们使用以下配置来连接到 MQTTS 上的 Mosca 经纪人：

```js
var client = mqtt.connect({
    port: config.mqtt.port,
    protocol: 'mqtts',
    host: config.mqtt.host,
    clientId: config.mqtt.clientId,
    reconnectPeriod: 1000,
    username: config.mqtt.clientId,
    password: config.mqtt.clientId,
    keepalive: 300,
    rejectUnauthorized: false
});
```

我们正在订阅两个事件：一个是在连接建立时，另一个是在接收消息时。在`connect`事件上，我们订阅了一个名为`greet`的主题，并在下一行发布了一个简单的消息到该主题。在`message`事件上，我们正在监听来自经纪人的任何消息，并打印主题和消息。

通过这样，我们已经了解了与`api-engine`一起工作所需的大部分代码。要启动`api-engine`，`cd`进入`chapter2/api-engine`文件夹，并运行以下命令：

```js
npm start  
```

这将在端口`9000`上启动一个新的 Express 服务器应用程序。

# API 引擎测试

为了快速检查我们创建的 API，我们将使用一个名为 Postman 的 Chrome 扩展。您可以从这里设置 Chrome 扩展：[`chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop?hl=en`](https://chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop?hl=en)。

一旦 Postman 设置好，我们将测试两个 API 调用以验证注册和登录方法。

打开 Postman，并输入请求的 URL 为`http://localhost:9000/api/v1/users`。接下来，选择方法类型为`POST`。完成后，我们将设置标头。添加一个新的标头，键为`content-type`，值为`application/json`。

现在我们将构建请求体/有效载荷。点击 Headers 旁边的 Body 选项卡，选择 Raw request。并更新为以下内容：

```js
{ 
   "email" : "arvind@myapp.com", 
   "password" : "123456", 
   "name" : "Arvind" 
} 
```

您可以根据需要更新数据。然后点击发送。这将向 API 引擎发出请求，API 引擎将将数据保存到数据库，并以新用户对象和授权令牌作出响应。

我们的输出应该如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00018.jpeg)

现在，如果我们再次点击发送按钮并使用相同的数据，我们应该会看到一个验证错误，类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00019.jpeg)

现在，为了验证新注册的用户，我们将向`http://localhost:9000/auth/local`发出请求，只包含电子邮件和密码。我们应该会看到类似以下内容的东西：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00020.jpeg)

这验证了我们创建的 API。

通过这样，我们完成了 API 引擎的演练。在下一节中，我们将集成`api-engine`与经纪人，并测试它们之间的连接。

# 经纪人和 API 引擎之间的通信

现在我们在云上完成了这两个软件，我们将对它们进行接口化。在`api-engine/server/config/environment/development.js`中，我们已经定义了`api-engine`需要连接到的经纪人 IP 和端口。

稍后，如果我们将这两个部分部署到不同的机器上，这就是我们更新 IP 和端口的地方，以便`api-engine`引用经纪人。

现在，为了测试通信，`cd`进入`chapter2/broker`文件夹，并运行以下命令：

```js
mosca -c index.js -v | pino  
```

我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00021.jpeg)

接下来，打开一个新的命令提示符/终端，`cd`进入`chapter2/api-engine`文件夹，并运行以下命令：

```js
npm start 
```

我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00022.jpeg)

API 引擎连接到 mLab MongoDB 实例，然后启动了一个新的 Express 服务器，最后连接到了 Mosca 经纪人，并发布了一条消息到 greet 主题。

现在，如果我们查看 Mosca 终端，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00023.jpeg)

经纪人记录了迄今为止发生的活动。一个客户端连接了用户名`API_Server_Dev`并订阅了一个名为 greet 的主题，**服务质量**（**QoS**）为`0`。

有了这个，我们的经纪人和 API 引擎之间的集成就完成了。

接下来，我们将转向 Raspberry Pi 3，并开始使用 MQTTS 客户端。

如果您对 MQTT 协议不熟悉，可以参考*MQTT Essentials: Part 1 - Introducing MQTT* ([`www.hivemq.com/blog/mqtt-essentials-part-1-introducing-mqtt`](http://www.hivemq.com/blog/mqtt-essentials-part-1-introducing-mqtt))以及后续部分。要了解更多关于 QoS 的信息，请参考*MQTT Essentials Part 6: Quality of Service 0, 1 & 2* ([`www.hivemq.com/blog/mqtt-essentials-part-6-mqtt-quality-of-service-levels`](https://www.hivemq.com/blog/mqtt-essentials-part-6-mqtt-quality-of-service-levels))。

# 树莓派软件

在这一部分，我们将构建所需的软件，使树莓派通过 Wi-Fi 路由器成为我们 Mosca 经纪人的客户端。

我们已经在数据流程图中看到了树莓派是如何站在传感器和 Mosca 经纪人之间的。现在我们将设置所需的代码和软件。

# 设置树莓派

在这一部分，我们将看看如何在树莓派上安装所需的软件。

树莓派安装了 Raspbian OS ([`www.raspberrypi.org/downloads/raspbian/`](https://www.raspberrypi.org/downloads/raspbian/))是必需的。在继续之前，Wi-Fi 应该已经设置并连接好。

如果您是第一次设置树莓派 3，请参考*在树莓派上安装 Node.js 的初学者指南* ([`thisdavej.com/beginners-guide-to-installing-node-js-on-a-raspberry-pi/`](http://thisdavej.com/beginners-guide-to-installing-node-js-on-a-raspberry-pi/))。但是，我们将涵盖 Node.js 部分，您可以在启动 Pi 并配置 Wi-Fi 之前参考。

操作系统安装完成后，启动树莓派并登录。此时，它将通过您自己的访问点连接到互联网，您应该能够正常浏览互联网。

我正在使用 VNC Viewer 从我的 Apple MacBook Pro 访问我的树莓派 3。这样，我不会总是连接到树莓派 3。

我们将从下载 Node.js 开始。打开一个新的终端并运行以下命令：

```js
$ sudo apt update
$ sudo apt full-upgrade 
```

这将升级所有需要升级的软件包。接下来，我们将安装最新版本的 Node.js。在撰写本文时，Node 7.x 是最新版本：

```js
$ curl -sL https://deb.nodesource.com/setup_7.x | sudo -E bash -
$ sudo apt install nodejs  
```

这将需要一些时间来安装，一旦安装完成，您应该能够运行以下命令来查看 Node.js 和`npm`的版本：

```js
node -v
npm -v  
```

有了这个，我们已经设置好了在 Raspberry Pi 3 上运行 MQTTS 客户端所需的软件。

# 树莓派 MQTTS 客户端

现在我们将使用 Node.js 的 MQTTS 客户端进行工作。

在树莓派 3 的桌面上，创建一个名为`pi-client`的文件夹。打开一个终端并`cd`到`pi-client`文件夹。

我们要做的第一件事是创建一个`package.json`文件。从`pi-client`文件夹内部运行以下命令：

```js
$ npm init
```

然后根据情况回答问题。完成后，我们将在 Raspberry Pi 3 上安装 MQTT.js ([`www.npmjs.com/package/mqtt`](https://www.npmjs.com/package/mqtt))。运行以下命令：

```js
$ npm install mqtt -save  
```

一旦这个安装也完成了，最终的`package.json`将与这个相同：

```js
{
    "name": "pi-client",
    "version": "0.1.0",
    "description": "",
    "main": "index.js",
    "scripts": {
        "start": "node index.js"
    },
    "keywords": ["pi", "mqtts"],
    "author": "Arvind Ravulavaru",
    "private": true,
    "license": "ISC",
    "dependencies": {
        "mqtt": "².7.1"
    }
}
```

请注意，我们已经添加了一个启动脚本来启动我们的`index.js`文件。我们将在片刻之后创建`index.js`文件。

接下来，在`pi-client`文件夹的根目录下，创建一个名为`config.js`的文件。更新`config.js`如下：

```js
module.exports = { 
    mqtt: { 
        host: '10.2.192.141', 
        clientId: 'rPI_3', 
        port: 8883 
    } 
}; 
```

请注意主机属性。这是设置为我的 MacBook 的 IP 地址，我的 MacBook 是我将运行 Mosca 经纪人 API 引擎的地方。确保它们三个（Mosca 经纪人、API 引擎和树莓派 3）都在同一个 Wi-Fi 网络上。

接下来，我们将编写所需的 MQTT 客户端代码。在`pi-client`文件夹的根目录下创建一个名为`index.js`的文件，并更新如下：

```js
var config = require('./config.js'); 
var mqtt = require('mqtt') 
var client = mqtt.connect({ 
    port: config.mqtt.port, 
    protocol: 'mqtts', 
    host: config.mqtt.host, 
    clientId: config.mqtt.clientId, 
    reconnectPeriod: 1000, 
    username: config.mqtt.clientId, 
    password: config.mqtt.clientId, 
    keepalive: 300, 
    rejectUnauthorized: false 
}); 

client.on('connect', function() { 
    client.subscribe('greet') 
    client.publish('greet', 'Hello, IoTjs!') 
}); 

client.on('message', function(topic, message) { 
    // message is Buffer 
    console.log('Topic >> ', topic); 
    console.log('Message >> ', message.toString()) 
}); 
```

这是我们在 API 引擎上编写的相同测试代码，用于测试连接。保存所有文件并转向您的 Mosca 经纪人。

# 经纪人和树莓派之间的通信

在本节中，我们将通过 MQTTS 在经纪人和树莓派之间进行通信。

转到`broker`文件夹并运行以下命令：

```js
mosca -c index.js -v | pino  
```

接下来，转到树莓派，`cd`进入`pi-client`文件夹，并运行以下命令：

```js
$ npm start  
```

我们应该在树莓派上看到以下消息：

>![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00024.jpeg)

当我们查看 Mosca 的控制台时，我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00025.jpeg)

这结束了我们在树莓派 3 和 Mosca 经纪人之间的连接测试。

# 故障排除

如果您无法看到以前的消息，请检查以下内容：

+   检查树莓派和运行经纪人的机器是否在同一个 Wi-Fi 网络上

+   检查运行经纪人的机器的 IP 地址

# 树莓派、经纪人和 API 引擎之间的通信

现在我们将集成树莓派、经纪人和 API 引擎，并将数据从树莓派传递到 API 引擎。

我们将实现这一点的方式是创建一个名为`api-engine`的主题和另一个名为`rpi`的主题。

要将数据从树莓派发送到 API 引擎，我们将使用`api-engine`主题，当我们需要将数据从 API 引擎发送到树莓派时，我们将使用`rpi`主题。

在这个例子中，我们将获取树莓派的 MAC 地址并将其发送到 API 引擎。API 引擎将通过将相同的 MAC 地址发送回树莓派来确认相同。API 引擎和树莓派之间的通信将在前面提到的两个主题上进行。

因此，首先，我们将按照以下方式更新`api-engine/server/mqtt/index.js`：

```js
var mqtt = require('mqtt'); 
var config = require('../config/environment'); 

var client = mqtt.connect({ 
    port: config.mqtt.port, 
    protocol: 'mqtts', 
    host: config.mqtt.host, 
    clientId: config.mqtt.clientId, 
    reconnectPeriod: 1000, 
    username: config.mqtt.clientId, 
    password: config.mqtt.clientId, 
    keepalive: 300, 
    rejectUnauthorized: false 
}); 

client.on('connect', function() { 
    client.subscribe('api-engine'); 
}); 

client.on('message', function(topic, message) { 
    // message is Buffer 
    // console.log('Topic >> ', topic); 
    // console.log('Message >> ', message.toString()); 
    if (topic === 'api-engine') { 
        var macAddress = message.toString(); 
        console.log('Mac Address >> ', macAddress); 
        client.publish('rpi', 'Got Mac Address: ' + macAddress); 
    } else { 
        console.log('Unknown topic', topic); 
    } 
}); 
```

在这里，一旦建立了 MQTT 连接，我们就会订阅`api-engine`主题。当我们从`api-engine`主题接收到任何数据时，我们将把相同的数据发送回`rpi`主题。

在`broker`文件夹中运行以下命令：

```js
mosca -c index.js -v | pino  
```

接下来，在`api-engine`文件夹中运行以下命令：

```js
npm start  
```

接下来，回到树莓派。我们将安装`getmac`模块（[`www.npmjs.com/package/getmac`](https://www.npmjs.com/package/getmac)），这将帮助我们获取设备的 MAC 地址。

在`pi-client`文件夹中运行以下命令：

```js
$ npm install getmac --save  
```

完成后，更新`/home/pi/Desktop/pi-client/index.js`如下：

```js
var config = require('./config.js'); 
var mqtt = require('mqtt'); 
var GetMac = require('getmac'); 

var client = mqtt.connect({ 
    port: config.mqtt.port, 
    protocol: 'mqtts', 
    host: config.mqtt.host, 
    clientId: config.mqtt.clientId, 
    reconnectPeriod: 1000, 
    username: config.mqtt.clientId, 
    password: config.mqtt.clientId, 
    keepalive: 300, 
    rejectUnauthorized: false 
}); 

client.on('connect', function() { 
    client.subscribe('rpi'); 
    GetMac.getMac(function(err, macAddress) { 
        if (err) throw err; 
        client.publish('api-engine', macAddress); 
    }); 
}); 

client.on('message', function(topic, message) { 
    // message is Buffer 
    // console.log('Topic >> ', topic); 
    // console.log('Message >> ', message.toString()); 
    if (topic === 'rpi') { 
        console.log('API Engine Response >> ', message.toString()); 
    } else { 
        console.log('Unknown topic', topic); 
    } 
}); 
```

在以前的代码中，我们等待树莓派和经纪人之间的连接建立。一旦完成，我们就订阅了`rpi`主题。接下来，我们使用`GetMac.getMac()`获取了树莓派的 MAC 地址，并将其发布到`api-engine`主题。

在`message`事件回调中，我们正在监听`rpi`主题。如果我们从服务器收到任何数据，它将在这里打印出来。

保存文件，并在`pi-client`文件夹中运行以下命令：

```js
$ npm start  
```

现在，如果我们查看经纪人终端/提示，我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00026.jpeg)

这两个设备都连接并订阅了感兴趣的主题。

接下来，如果我们查看`api-engine`终端/提示，我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00027.jpeg)

最后，树莓派终端应该看起来与这个一样：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00028.jpeg)

有了这个，我们完成了树莓派与经纪人和 API 引擎的集成。

在下一节中，我们将实现一个 Web 应用程序，该应用程序可以通过经纪人和 API 引擎与树莓派发送和接收数据。

# Web 应用程序

在本节中，我们将构建一个与我们的 API 引擎进行交互的 Web 应用程序。Web 应用程序是我们将与智能设备进行交互的主要界面。

我们将使用 Angular (4)和 Twitter Bootstrap (3)构建 Web 应用程序。界面不一定要使用 Angular 和 Bootstrap 构建；也可以使用 jQuery 或 React.js。我们将做的只是使用浏览器中的 JavaScript 与 API 引擎的 API 进行接口。我们之所以使用 Angular，只是为了保持所有应用程序的框架一致。由于我们将使用 Ionic 框架，它也遵循 Angular 的方法，因此对我们来说管理和重用都会很容易。

要开始使用 Web 应用程序，我们将安装 Angular CLI ([`github.com/angular/angular-cli`](https://github.com/angular/angular-cli))。

在运行我们的代理和 API 引擎的机器上，我们也将设置 Web 应用程序。

# 设置应用程序

从`chapter2`文件夹内，打开一个新的命令提示符/终端，并运行以下命令：

```js
npm install -g @angular/cli  
```

这将安装 Angular CLI 生成器。安装完成后运行`ng -v`，您应该看到一个大于或等于 1.0.2 的版本号。

如果在设置和运行 IoTFW.js 时遇到任何问题，请随时在此处留下您的评论：[`github.com/PacktPublishing/Practical-Internet-of-Things-with-JavaScript/issues/1`](https://github.com/PacktPublishing/Practical-Internet-of-Things-with-JavaScript/issues/1)

对于 Web 应用程序，我们已经使用 Angular CLI 创建了一个基本项目，并添加了必要的部分来与 API 引擎集成。我们将克隆项目并在此基础上开始工作。

要开始，我们需要 Web 应用程序的基础。如果您还没有克隆该书的代码存储库，可以在您的任何位置使用以下命令行进行克隆：

```js
git clone git@github.com:PacktPublishing/Practical-Internet-of-Things-with-JavaScript.git
```

或者您也可以从[`github.com/PacktPublishing/Practical-Internet-of-Things-with-JavaScript`](https://github.com/PacktPublishing/Practical-Internet-of-Things-with-JavaScript)下载 zip 文件。

一旦存储库被下载，`cd`进入`base`文件夹，并将`web-app-base`文件夹复制到`chapter2`文件夹中。

基础已经复制完成后，`cd`进入`web-app`文件夹，并运行以下命令：

```js
npm install  
```

这将安装所需的依赖项。

# 项目结构

如果打开`cloned`文件夹，我们应该看到以下内容：

```js
.
├── README.md
├── e2e
│ ├── app.e2e-spec.ts
│ ├── app.po.ts
│ └── tsconfig.e2e.json
├── karma.conf.js
├── package.json
├── protractor.conf.js
├── src
│ ├── app
│ │ ├── add-device
│ │ │ ├── add-device.component.css
│ │ │ ├── add-device.component.html
│ │ │ ├── add-device.component.spec.ts
│ │ │ └── add-device.component.ts
│ │ ├── app.component.css
│ │ ├── app.component.html
│ │ ├── app.component.spec.ts
│ │ ├── app.component.ts
│ │ ├── app.global.ts
│ │ ├── app.module.ts
│ │ ├── device
│ │ │ ├── device.component.css
│ │ │ ├── device.component.html
│ │ │ ├── device.component.spec.ts
│ │ │ └── device.component.ts
│ │ ├── device-template
│ │ │ ├── device-template.component.css
│ │ │ ├── device-template.component.html
│ │ │ ├── device-template.component.spec.ts
│ │ │ └── device-template.component.ts
│ │ ├── guard
│ │ │ ├── auth.guard.spec.ts
│ │ │ └── auth.guard.ts
│ │ ├── home
│ │ │ ├── home.component.css
│ │ │ ├── home.component.html
│ │ │ ├── home.component.spec.ts
│ │ │ └── home.component.ts
│ │ ├── login
│ │ │ ├── login.component.css
│ │ │ ├── login.component.html
│ │ │ ├── login.component.spec.ts
│ │ │ └── login.component.ts
│ │ ├── nav-bar
│ │ │ ├── nav-bar.component.css
│ │ │ ├── nav-bar.component.html
│ │ │ ├── nav-bar.component.spec.ts
│ │ │ └── nav-bar.component.ts
│ │ ├── register
│ │ │ ├── register.component.css
│ │ │ ├── register.component.html
│ │ │ ├── register.component.spec.ts
│ │ │ └── register.component.ts
│ │ └── services
│ │ ├── auth.service.spec.ts
│ │ ├── auth.service.ts
│ │ ├── data.service.spec.ts
│ │ ├── data.service.ts
│ │ ├── devices.service.spec.ts
│ │ ├── devices.service.ts
│ │ ├── http-interceptor.service.spec.ts
│ │ ├── http-interceptor.service.ts
│ │ ├── loader.service.spec.ts
│ │ ├── loader.service.ts
│ │ ├── socket.service.spec.ts
│ │ └── socket.service.ts
│ ├── assets
│ ├── environments
│ │ ├── environment.prod.ts
│ │ └── environment.ts
│ ├── favicon.ico
│ ├── index.html
│ ├── main.ts
│ ├── polyfills.ts
│ ├── styles.css
│ ├── test.ts
│ ├── tsconfig.app.json
│ ├── tsconfig.spec.json
│ └── typings.d.ts
├── tsconfig.json
└── tslint.json
```

现在，让我们来看一下项目结构和代码设置的步骤。

在高层次上，我们有一个`src`文件夹，其中包含所有的源代码和单元测试代码，还有一个`e2e`文件夹，其中包含端到端测试。

我们将大部分时间花在`src/app`文件夹内。在进入这个文件夹之前，打开`web-app/src/main.ts`，这是一切的开始。接下来，我们在这里添加了 Twitter Bootstrap Cosmos 主题([`bootswatch.com/cosmo/`](https://bootswatch.com/cosmo/))，并定义了一些布局样式。

现在，`app/src`文件夹：在这里，我们定义了根组件、根模块和所需的组件和服务。

# 应用模块

打开`web-app/src/app/app.module.ts`。这个文件包括`@NgModule`声明，定义了我们将要使用的所有组件和服务。

我们已经创建了以下组件：

+   `AppComponent`：应用程序根组件，包含路由出口

+   `NavBarComponent`：这是出现在所有页面上的导航栏组件。该组件会自动检测认证状态，并相应地显示菜单栏

+   `LoginComponent`：处理登录功能

+   `RegisterComponent`：用于与 API 引擎进行注册

+   `HomeComponent`：这个组件显示当前登录用户附加的所有设备

+   `DeviceComponent`：这个组件显示有关一个设备的信息

+   `AddDeviceComponent`：这个组件让我们向设备列表中添加新的组件

+   `DeviceTemplateComponent`：用于表示应用程序中设备的通用模板

除了上述内容，我们还添加了所需的模块到导入中：

+   路由模块：用于管理路由

+   `LocalStorageModule`：为了在浏览器中管理用户数据，我们将使用`LocalStorgae`

+   `SimpleNotificationsModule`：使用 Angular 2 通知显示通知（[`github.com/flauc/angular2-notifications`](https://github.com/flauc/angular2-notifications)）

对于服务，我们有以下内容：

+   `AuthService`：管理 API 引擎提供的身份验证 API

+   `DevicesService`：管理 API 引擎提供的设备 API

+   `DataService`：管理 API 引擎提供的数据 API

+   `SocketService`：管理从 API 引擎实时发送数据的 Web 套接字

+   `AuthGuard`：一个 Angular 守卫，用于保护需要身份验证的路由。阅读*使用 Angular 中的守卫保护路由*（[`blog.thoughtram.io/angular/2016/07/18/guards-in-angular-2.html`](https://blog.thoughtram.io/angular/2016/07/18/guards-in-angular-2.html)）获取有关守卫的更多信息

+   `LoaderService`：在进行活动时显示和隐藏加载器栏

+   `Http`：我们用来发出 HTTP 请求的 HTTP 服务。在这里，我们没有直接使用 HTTP 服务，而是扩展了该类，并在其中添加了我们的逻辑，以更好地使用加载器服务来管理 HTTP 请求体验

请注意，此时 API 引擎没有设备和数据的 API，并且数据的套接字未设置。一旦我们完成 Web 应用程序，我们将在 API 引擎中实现它。

在这个 Web 应用程序中，我们将有以下路由：

+   `login`：让用户登录应用程序

+   `register`：注册我们的应用程序

+   `home`：显示用户帐户中所有设备的页面

+   `add-device`：向用户的设备列表添加新设备的页面

+   `view-device/:id`：查看由 URL 中的 id 参数标识的一个设备的页面

+   `**`：默认路由设置为登录

+   `''`：如果没有匹配的路由，我们将用户重定向到登录页面

# Web 应用程序服务

现在我们在高层次上了解了这个 Web 应用程序中的所有内容，我们将逐步介绍服务和组件。

打开`web-app/src/app/services/http-interceptor.service.ts`；在这个类中，我们扩展了`Http`类并实现了类方法。我们添加了两个自己的方法，名为`requestInterceptor()`和`responseInterceptor()`，分别拦截请求和响应。

当请求即将发送时，我们调用`requestInterceptor()`来显示加载器，指示 HTTP 活动，我们使用`responseInterceptor()`一旦响应到达就隐藏加载器。这样，用户清楚地知道是否有任何后台活动正在进行。

接下来是`LoaderService`类；打开`web-app/src/app/services/loader.service.ts`，从这里我们可以看到，我们添加了一个名为`status`的类属性，类型为`BehaviorSubject<boolean>`（要了解更多关于`Behavior`主题的信息，请参阅[`github.com/Reactive-Extensions/RxJS/blob/master/doc/api/subjects/behaviorsubject.md`](https://github.com/Reactive-Extensions/RxJS/blob/master/doc/api/subjects/behaviorsubject.md)）。我们还有一个方法，如果 HTTP 服务或任何其他组件希望显示或隐藏加载器栏，它们将调用该方法，然后将值设置为 true 或 false。

加载器服务所需的 HTML 位于`web-app/src/app/app.component.html`，所需的样式位于`web-app/src/app/app.component.css`。

我们将使用 Web 套接字在 Web 应用程序和 API 引擎之间实时流式传输数据。打开`web-app/src/app/services/socket.service.ts`，我们应该看到构造函数和`getData()`方法。我们在我们的 Web 应用程序中使用`socket.io-client`（[`github.com/socketio/socket.io-client`](https://github.com/socketio/socket.io-client)）来管理 Web 套接字。

在构造函数中，我们已经创建了一个新的套接字连接到我们的 API 引擎，并将身份验证令牌作为查询参数传递。我们也将通过 Web 套接字验证传入的连接。只有在令牌有效的情况下，我们才允许连接，否则我们关闭 Web 套接字。

在`getData()`内，我们订阅了设备的`data:save`主题。这是我们从 API 引擎得到通知的方式，当设备有新数据可用时。

现在我们将查看三个 API 服务，用于验证用户，获取用户设备和获取设备数据：

+   `AuthService`：打开`web-app/src/app/services/auth.service.ts`。在这里，我们已经定义了`register()`，`login()`和`logout()`，它们负责管理身份验证状态，我们还有`isAuthenticated()`，它返回当前的身份验证状态，即用户是已登录还是已注销。

+   `DevicesService`：打开`web-app/src/app/services/devices.service.ts`。在这里，我们实现了三种方法：创建一个，读取一个，删除一个。通过这样，我们为用户管理我们的设备。

+   `DataService`：打开`web-app/src/app/services/data.service.ts`，它管理设备的数据。我们这里只有两种方法：创建一个新的数据记录和获取设备的最后 30 条记录。

请注意，我们正在使用`web-app/src/app/app.global.ts`来保存所有我们的常量全局变量。

现在我们已经完成了所需的服务，我们将浏览组件。

# Web 应用程序组件

我们将从应用程序组件开始。应用程序组件是根组件，它包含路由器出口，加载器服务 HTML 和通知服务 HTML。您可以在这里找到相同的内容：`web-app/src/app/app.component.html`。在`web-app/src/app/app.component.ts`中，我们已经定义了`showLoader`，它决定是否应该显示加载器。我们还定义了通知选项，它存储通知服务的配置。

在构造函数内，我们正在监听路由器上的路由更改事件，以便在页面更改时显示加载栏。我们还在监听加载器服务状态变量。如果这个变化，我们就会显示或隐藏加载器。

用户登陆的第一个页面是登录页面。登录页面/组件`web-app/src/app/login/login.component.ts`只有一个方法，从`web-app/src/app/login/login.component.html`获取用户的电子邮件和密码，并对用户进行身份验证。

使用主页上的注册按钮，用户注册自己。在`RegisterComponent`类内，`web-app/src/app/register/register.component.ts`，我们已经定义了`register()`，它获取用户的信息，并使用`AuthService`注册用户。

一旦用户成功验证，我们将用户重定向到`LoginComponent`。在`HomeComponent`，`web-app/src/app/home/home.component.ts`中，我们获取与用户关联的所有设备并在加载时显示它们。此页面还有一个按钮，用于使用`AddDeviceComponent`添加新设备。

要查看一个设备，我们使用`DeviceComponent`来查看一个设备。

目前，我们还没有任何可用于处理设备和数据的 API。在下一节中完成 API 引擎更新后，我们将重新访问此页面。

# 启动应用程序

要运行应用程序，请在`web-app`文件夹内打开终端/提示符，并运行以下命令：

```js
ng serve
```

在运行上一个命令之前，请确保 API 引擎和 Mosca 正在运行。

一旦 webpack 编译成功，导航到`http://localhost:4200/login`，我们应该看到登录页面，这是第一个页面。

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00029.jpeg)

我们可以使用在测试 API 引擎时创建的帐户，使用 Postman，或者我们可以通过点击“使用 Web 应用程序注册”来创建一个新帐户，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00030.jpeg)

如果注册成功，我们应该被重定向到主页，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00031.jpeg)

如果我们打开开发者工具，应该会看到先前的消息。API 引擎没有实现设备的 API，因此出现了先前的“404”。我们将在第三章中修复这个问题，*IoTFW.js - II*。

我们还将在第三章中逐步完成 Web 应用程序的剩余部分，一旦 API 引擎更新完成。

# 总结

在本章中，我们已经了解了建立物联网解决方案的过程。我们使用 JavaScript 作为编程语言构建了大部分框架。

我们首先了解了从树莓派到 Web 应用程序、桌面应用程序或移动应用程序等最终用户设备的架构和数据流。然后我们开始使用 Mosca 工作代理，设置了 MongoDB。接下来，我们设计并开发了 API 引擎，并完成了基本的树莓派设置。

我们已经在 Web 应用程序上工作，并设置了必要的模板，以便与应用程序的剩余部分配合使用。在第三章中，我们将完成整个框架，并集成 DHT11（温湿度）传感器和 LED，以验证端到端的双向数据流。


# 第三章：IoTFW.js - II

在上一章中，我们已经看到了树莓派、代理、API 引擎和 Web 应用程序之间的基本设置。在本章中，我们将继续处理框架的其余部分。我们还将构建一个涉及传感和执行的简单示例。我们将使用温湿度传感器读取温度和湿度，并使用 Web、桌面或移动应用程序打开/关闭连接到我们的树莓派的 LED。

在本章中，我们将涵盖以下主题：

+   更新 API 引擎

+   将 API 引擎与 Web 应用程序集成

+   使用 DHT11 和 LED 构建端到端示例

+   构建桌面应用程序

+   构建移动应用程序

# 更新 API 引擎

现在我们已经完成了 Web 应用程序的开发，我们将更新 API 引擎以添加设备的 API 和数据服务，以及 Web 套接字。

打开`api-engine/server/routes.js`；我们将在这里添加两个路由。更新`api-engine/server/routes.js`如下：

```js
'use strict'; 

var path = require('path'); 

module.exports = function(app) { 
  // Insert routes below 
  app.use('/api/v1/users', require('./api/user')); 
  app.use('/api/v1/devices', require('./api/device')); 
  app.use('/api/v1/data', require('./api/data')); 

  app.use('/auth', require('./auth')); 
}; 
```

现在，我们将为这些路由添加定义。在`api-engine/server/api`文件夹内，创建一个名为`device`的新文件夹。在`device`文件夹内，创建一个名为`index.js`的新文件。更新`api-engine/server/api/device/index.js`如下：

```js
'use strict'; 

var express = require('express'); 
var controller = require('./device.controller'); 
var config = require('../../config/environment'); 
var auth = require('../../auth/auth.service'); 

var router = express.Router(); 

router.get('/', auth.isAuthenticated(), controller.index); 
router.delete('/:id', auth.isAuthenticated(), controller.destroy); 
router.put('/:id', auth.isAuthenticated(), controller.update); 
router.get('/:id', auth.isAuthenticated(), controller.show); 
router.post('/', auth.isAuthenticated(), controller.create); 

module.exports = router; 
```

在这里，我们添加了五个路由，如下：

+   获取所有设备

+   删除设备

+   更新设备

+   获取一个设备

+   创建一个设备

接下来，在`api-engine/server/api/device/`文件夹内创建另一个文件，命名为`device.model.js`。这个文件将包含设备集合的 mongoose 模式。更新`api-engine/server/api/device/device.model.js`如下：

```js
'use strict'; 

var mongoose = require('mongoose'); 
var Schema = mongoose.Schema; 

var DeviceSchema = new Schema({ 
    name: String, 
    macAddress: String, 
    createdBy: { 
        type: String, 
        default: 'user' 
    }, 
    createdAt: { 
        type: Date 
    }, 
    updatedAt: { 
        type: Date 
    } 
}); 

DeviceSchema.pre('save', function(next) { 
    var now = new Date(); 
    this.updatedAt = now; 
    if (!this.createdAt) { 
        this.createdAt = now; 
    } 
    next(); 
}); 

module.exports = mongoose.model('Device', DeviceSchema); 
```

最后，控制器逻辑。在`api-engine/server/api/device`文件夹内创建一个名为`device.controller.js`的文件，并更新`api-engine/server/api/device/device.controller.js`如下：

```js
'use strict'; 

var Device = require('./device.model'); 

/** 
 * Get list of all devices for a user 
 */ 
exports.index = function(req, res) { 
    var currentUser = req.user._id; 
    // get only devices related to the current user 
    Device.find({ 
        createdBy: currentUser 
    }, function(err, devices) { 
        if (err) return res.status(500).send(err); 
        res.status(200).json(devices); 
    }); 
}; 

/** 
 * Add a new device 
 */ 
exports.create = function(req, res, next) { 
    var device = req.body; 
    // this device is created by the current user 
    device.createdBy = req.user._id; 
    Device.create(device, function(err, device) { 
        if (err) return res.status(500).send(err); 
        res.json(device); 
    }); 
}; 

/** 
 * Get a single device 
 */ 
exports.show = function(req, res, next) { 
    var deviceId = req.params.id; 
    // the current user should have created this device 
    Device.findOne({ 
        _id: deviceId, 
        createdBy: req.user._id 
    }, function(err, device) { 
        if (err) return res.status(500).send(err); 
        if (!device) return res.status(404).end(); 
        res.json(device); 
    }); 
}; 

/** 
 * Update a device 
 */ 
exports.update = function(req, res, next) { 
    var device = req.body; 
    device.createdBy = req.user._id; 

    Device.findOne({ 
        _id: deviceId, 
        createdBy: req.user._id 
    }, function(err, device) { 
        if (err) return res.status(500).send(err); 
        if (!device) return res.status(404).end(); 

        device.save(function(err, updatedDevice) { 
            if (err) return res.status(500).send(err); 
            return res.status(200).json(updatedDevice); 
        }); 
    }); 
}; 

/** 
 * Delete a device 
 */ 
exports.destroy = function(req, res) { 
    Device.findOne({ 
        _id: req.params.id, 
        createdBy: req.user._id 
    }, function(err, device) { 
        if (err) return res.status(500).send(err); 

        device.remove(function(err) { 
            if (err) return res.status(500).send(err); 
            return res.status(204).end(); 
        }); 
    }); 
}; 
```

在这里，我们已经定义了路由的逻辑。

设备 API 为我们管理设备。为了管理每个设备的数据，我们将使用这个集合。

现在，我们将定义数据 API。在`api-engine/server/api`文件夹内创建一个名为`data`的新文件夹。在`api-engine/server/api/data`文件夹内，创建一个名为`index.js`的新文件，并更新`api-engine/server/api/data/index.js`如下：

```js
'use strict'; 

var express = require('express'); 
var controller = require('./data.controller'); 
var auth = require('../../auth/auth.service'); 

var router = express.Router(); 

router.get('/:deviceId/:limit', auth.isAuthenticated(), controller.index); 
router.post('/', auth.isAuthenticated(), controller.create); 

module.exports = router; 
```

我们在这里定义了两个路由：一个用于基于设备 ID 查看数据，另一个用于创建数据。查看数据路由返回作为请求的一部分传递的数量限制的设备数据。如果您记得，在`web-app/src/app/services/data.service.ts`中，我们已经将`dataLimit`类变量定义为`30`。这是我们从 API 中一次获取的记录数。

接下来，对于 mongoose 模式，在`api-engine/server/api/data`文件夹内创建一个名为`data.model.js`的新文件，并更新`api-engine/server/api/data/data.model.js`如下：

```js
'use strict'; 

var mongoose = require('mongoose'); 
var Schema = mongoose.Schema; 

var DataSchema = new Schema({ 
    macAddress: { 
        type: String 
    }, 
    data: { 
        type: Schema.Types.Mixed 
    }, 
    createdBy: { 
        type: String, 
        default: 'raspberrypi3' 
    }, 
    createdAt: { 
        type: Date 
    }, 
    updatedAt: { 
        type: Date 
    } 
}); 

DataSchema.pre('save', function(next) { 
    var now = new Date(); 
    this.updatedAt = now; 
    if (!this.createdAt) { 
        this.createdAt = now; 
    } 
    next(); 
});
```

```js
DataSchema.post('save', function(doc) { 
    //console.log('Post Save Called', doc); 
    require('./data.socket.js').onSave(doc) 
}); 

module.exports = mongoose.model('Data', DataSchema); 
```

现在，数据 API 的控制器逻辑。在`api-engine/server/api/data`文件夹内创建一个名为`data.controller.js`的文件，并更新`api-engine/server/api/data/data.controller.js`如下：

```js
'use strict'; 

var Data = require('./data.model'); 

/** 
 * Get Data for a device 
 */ 
exports.index = function(req, res) { 
    var macAddress = req.params.deviceId; 
    var limit = parseInt(req.params.limit) || 30; 
    Data.find({ 
        macAddress: macAddress 
    }).limit(limit).exec(function(err, devices) { 
        if (err) return res.status(500).send(err); 
        res.status(200).json(devices); 
    }); 
}; 

/** 
 * Create a new data record 
 */ 
exports.create = function(req, res, next) { 
    var data = req.body; 
    data.createdBy = req.user._id; 
    Data.create(data, function(err, _data) { 
        if (err) return res.status(500).send(err); 
        res.json(_data); 
        if(data.topic === 'led'){ 
            require('../../mqtt/index.js').sendLEDData(data.data.l);// send led value 
        } 
    }); 
}; 
```

在这里，我们定义了两种方法：一种是为设备获取数据，另一种是为设备创建新的数据记录。

对于数据 API，我们也将实现套接字，因此当来自树莓派的新记录时，我们立即通知 Web 应用程序、桌面应用程序或移动应用程序，以便数据可以实时显示。

从前面的代码中可以看到，如果传入的主题是`LED`，我们将调用`sendLEDData()`，它会将数据发布到设备。

在`api-engine/server/api/data`文件夹内创建一个名为`data.socket.js`的文件，并更新`api-engine/server/api/data/data.socket.js`如下：

```js
/** 
 * Broadcast updates to client when the model changes 
 */ 

'use strict'; 

var data = require('./data.model'); 
var socket = undefined; 

exports.register = function(_socket) { 
   socket = _socket; 
} 

function onSave(doc) { 
    // send data to only the intended device 
    socket.emit('data:save:' + doc.macAddress, doc); 
} 

module.exports.onSave = onSave; 
```

这将负责在成功保存到数据库后发送新的数据记录。

接下来，我们需要将 socket 添加到 socket 配置中。打开`api-engine/server/config/socketio.js`并进行更新如下：

```js
'use strict'; 

var config = require('./environment'); 

// When the user disconnects.. perform this 
function onDisconnect(socket) {} 

// When the user connects.. perform this 
function onConnect(socket) { 
    // Insert sockets below 
    require('../api/data/data.socket').register(socket); 
} 
module.exports = function(socketio) { 
    socketio.use(require('socketio-jwt').authorize({ 
        secret: config.secrets.session, 
        handshake: true 
    })); 

    socketio.on('connection', function(socket) { 
        var socketId = socket.id; 
        var clientIp = socket.request.connection.remoteAddress; 

        socket.address = socket.handshake.address !== null ? 
            socket.handshake.address.address + ':' + socket.handshake.address.port : 
            process.env.DOMAIN; 

        socket.connectedAt = new Date(); 

        // Call onDisconnect. 
        socket.on('disconnect', function() { 
            onDisconnect(socket); 
            // console.info('[%s] DISCONNECTED', socket.address); 
        }); 

        // Call onConnect. 
        onConnect(socket); 
        console.info('[%s] Connected on %s', socketId, clientIp); 
    }); 
}; 
```

请注意，我们使用`socketio-jwt`来验证套接字连接，以查看它是否具有 JWT。如果没有提供有效的 JWT，我们不允许客户端连接。

通过这样，我们完成了对 API 引擎的所需更改。保存所有文件并通过运行以下命令启动 API 引擎：

```js
npm start  
```

这将启动 API 引擎。在下一节中，我们将测试 Web 应用程序和 API 引擎之间的集成，并继续从上一节开始的步骤。

# 集成 Web 应用程序和 API 引擎

启动代理商、API 引擎和 Web 应用程序。一旦它们都成功启动，导航到`http://localhost:4200/`。使用我们创建的凭据登录。一旦成功登录，我们应该看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00032.jpeg)

这是真的，因为我们的账户中没有任何设备。点击添加设备，我们应该看到如下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00033.jpeg)

通过给设备命名来添加一个新设备。我给我的设备命名为`Pi 1`并添加了 mac 地址。我们将使用设备的 mac 地址作为识别设备的唯一方式。

点击创建，我们应该看到一个新设备被创建，它将重定向我们到主页并显示新创建的设备，可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00034.jpeg)

现在，当我们点击查看按钮时，我们应该看到以下页面：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00035.jpeg)

在本书的示例中，我们将不断更新此模板，并根据需要进行修改。目前，这是一个由`web-app/src/app/device/device.component.html`表示的虚拟模板。

如果我们打开开发者工具并查看网络选项卡 WS 部分，如下截图所示，我们应该能够看到一个带有 JWT 令牌的 Web 套接字请求被发送到我们的服务器：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00036.jpeg)

通过这样，我们完成了将树莓派与代理商、代理商与 API 引擎以及 API 引擎与 Web 应用程序连接起来。为了完成从设备到 Web 应用程序的整个数据往返，我们将在下一节实现一个简单的用例。

# 使用 DHT11 和 LED 测试端到端流程

在开始处理桌面和移动应用程序之前，我们将为树莓派到 Web 应用程序的端到端数据流实现一个流程。

我们将要处理的示例实现了执行器和传感器用例。我们将把 LED 连接到树莓派，并从 Web 应用程序中打开/关闭 LED，我们还将把 DHT11 温度传感器连接到树莓派，并在 Web 应用程序中实时查看其值。

我们将开始使用树莓派，在那里实现所需的逻辑；接下来，与 API 引擎一起工作，进行所需的更改，最后是 Web 应用程序来表示数据。

# 设置和更新树莓派

首先，我们将按照以下方式设置电路：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00037.jpeg)

现在，我们将进行以下连接：

| **源引脚** | **组件引脚** |
| --- | --- |
| 树莓派引脚 1 - 3.3V | 面包板+栏杆 |
| 树莓派引脚 6 - 地面 | 面包板-栏杆 |
| 树莓派引脚 3 - GPIO 2 | 温度传感器信号引脚 |
| 树莓派引脚 12 - GPIO 18 | LED 阳极引脚 |
| LED 阴极引脚 | 面包板-栏杆 |
| 温度传感器+引脚 | 面包板+栏杆 |
| 温度传感器-引脚 | 面包板-栏杆 |

我们在引脚 12/GPIO 18 和 LED 引脚的阳极之间使用了一个 220 欧姆的限流电阻。

一旦建立了这种连接，我们将编写所需的逻辑。在树莓派上，打开`pi-client/index.js`文件并更新如下：

```js
var config = require('./config.js'); 
var mqtt = require('mqtt'); 
var GetMac = require('getmac'); 
var rpiDhtSensor = require('rpi-dht-sensor'); 
var rpio = require('rpio'); 
var dht11 = new rpiDhtSensor.DHT11(2); 
var temp = 0, 
    prevTemp = 0; 
var humd = 0, 
    prevHumd = 0; 
var macAddress; 
var state = 0; 

// Set pin 12 as output pin and to low 
rpio.open(12, rpio.OUTPUT, rpio.LOW); 

var client = mqtt.connect({ 
    port: config.mqtt.port, 
    protocol: 'mqtts', 
    host: config.mqtt.host, 
    clientId: config.mqtt.clientId, 
    reconnectPeriod: 1000, 
    username: config.mqtt.clientId, 
    password: config.mqtt.clientId, 
    keepalive: 300, 
    rejectUnauthorized: false 
}); 

client.on('connect', function() { 
    client.subscribe('rpi'); 
    client.subscribe('led'); 
    GetMac.getMac(function(err, mac) { 
        if (err) throw err; 
        macAddress = mac; 
        client.publish('api-engine', mac); 
    }); 
}); 

client.on('message', function(topic, message) { 
    message = message.toString(); 
    if (topic === 'rpi') { 
        console.log('API Engine Response >> ', message); 
    } else if (topic === 'led') { 
        state = parseInt(message) 
        console.log('Turning LED', state ? 'On' : 'Off'); 
        // If we get a 1 we turn on the led, else off 
        rpio.write(12, state ? rpio.HIGH : rpio.LOW); 
    } else { 
        console.log('Unknown topic', topic); 
    } 
}); 

// infinite loop, with 3 seconds delay 
setInterval(function() { 
    getDHT11Values(); 
    console.log('Temperature: ' + temp + 'C, ' + 'humidity: ' + humd + '%'); 
    // if the temperature and humidity values change 
    // then only publish the values 
    if (temp !== prevTemp || humd !== prevHumd) { 
        var data2Send = { 
            data: { 
                t: temp, 
                h: humd, 
                l: state 
            }, 
            macAddress: macAddress 
        }; 
        console.log('Data Published'); 
        client.publish('dht11', JSON.stringify(data2Send)); 
        // reset prev values to current 
        // for next loop 
        prevTemp = temp; 
        prevHumd = humd; 
    } // else chill! 

}, 3000); // every three second 

function getDHT11Values() { 
    var readout = dht11.read(); 
    // update global variable 
    temp = readout.temperature.toFixed(2); 
    humd = readout.humidity.toFixed(2); 
} 
```

在上述代码中，我们添加了一些节点模块，如下所示：

+   `rpi-dht-sensor`: [`www.npmjs.com/package/rpi-dht-sensor`](https://www.npmjs.com/package/rpi-dht-sensor)；这个模块将帮助我们读取 DHT11 传感器的值

+   `rpio`: [`www.npmjs.com/package/rpio`](https://www.npmjs.com/package/rpio)；这个模块将帮助我们管理板上的 GPIO，我们将使用它来管理 LED

我们编写了一个`setInterval()`，它会每 3 秒运行一次。在`callback`中，我们调用`getDHT11Values()`来从传感器读取温度和湿度。如果温度和湿度值发生变化，我们就会将这些数据发布到代理。

还要注意`client.on('message')`；在这里，我们添加了另一个`if`条件，并监听`LED`主题。如果当前消息来自`LED`主题，我们知道我们将收到一个`1`或`0`，表示打开或关闭 LED。

最后，我们将安装这两个模块，运行：

```js
npm install rpi-dht-sensor -save
npm install rpio -save  
```

保存所有文件并运行`npm start`；这应该将树莓派连接到代理并订阅`LED`主题，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00038.jpeg)

此外，如果我们从树莓派的控制台输出中看到，应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00039.jpeg)

每当数据发生变化时，数据就会发布到代理。我们还没有实现对 API 引擎上的数据做出反应的逻辑，这将在下一节中完成。

# 更新 API 引擎

现在，我们将向在 API 引擎上运行的 MQTT 客户端添加所需的代码来处理来自设备的数据。更新`api-engine/server/mqtt/index.js`，如下所示：

```js
var Data = require('../api/data/data.model'); 
var mqtt = require('mqtt'); 
var config = require('../config/environment'); 

var client = mqtt.connect({ 
    port: config.mqtt.port, 
    protocol: 'mqtts', 
    host: config.mqtt.host, 
    clientId: config.mqtt.clientId, 
    reconnectPeriod: 1000, 
    username: config.mqtt.clientId, 
    password: config.mqtt.clientId, 
    keepalive: 300, 
    rejectUnauthorized: false 
}); 

client.on('connect', function() { 
    console.log('Connected to Mosca at ' + config.mqtt.host + ' on port ' + config.mqtt.port); 
    client.subscribe('api-engine'); 
    client.subscribe('dht11'); 
}); 

client.on('message', function(topic, message) { 
    // message is Buffer 
    // console.log('Topic >> ', topic); 
    // console.log('Message >> ', message.toString()); 
    if (topic === 'api-engine') { 
        var macAddress = message.toString(); 
        console.log('Mac Address >> ', macAddress); 
        client.publish('rpi', 'Got Mac Address: ' + macAddress); 
    } else if (topic === 'dht11') { 
        var data = JSON.parse(message.toString()); 
        // create a new data record for the device 
        Data.create(data, function(err, data) { 
            if (err) return console.error(err); 
            // if the record has been saved successfully,  
            // websockets will trigger a message to the web-app 
            console.log('Data Saved :', data.data); 
        }); 
    } else { 
        console.log('Unknown topic', topic); 
    } 
}); 

exports.sendLEDData = function(data) { 
    console.log('Sending Data', data); 
    client.publish('led', data); 
} 
```

在这里，我们订阅了一个名为`dht11`的主题，以监听树莓派发布的关于温度和湿度值的消息。我们还公开了另一个名为`sendLEDData`的方法，用于接受需要发送到设备的数据。

如果我们保存所有文件并重新启动 API 引擎，应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00040.jpeg)

从上面的截图中，我们可以看到数据来自树莓派并保存到 MongoDB。要验证数据是否已保存，我们可以转到`mlab`数据库并查找名为`datas`的集合，应该如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00041.jpeg)

每当数据成功保存时，相同的副本也将发送到 Web 应用程序。在下一节中，我们将在 Web 仪表板上实时显示这些数据。

# 更新 Web 应用程序

在本节中，我们将开发在 Web 应用程序中实时显示数据所需的代码，以及提供一个界面，通过该界面我们可以打开/关闭 LED。

我们将首先添加一个切换开关组件。我们将使用`ngx-ui-switch` ([`github.com/webcat12345/ngx-ui-switch`](https://github.com/webcat12345/ngx-ui-switch))。

从`web-app-base`文件夹内运行以下命令：

```js
npm install ngx-ui-switch -save  
```

我们将使用`ng2-charts` [`valor-software.com/ng2-charts/`](https://valor-software.com/ng2-charts/)来绘制温度和湿度值的图表。我们也将通过运行以下命令安装这个模块：

```js
npm install ng2-charts --save
npm install chart.js --save  
```

这将安装切换开关和`ng2-charts`模块。接下来，我们需要将其添加到`@NgModule`中。打开`web-app/src/app/app.module.ts`并将以下命令添加到 imports 中：

```js
import { UiSwitchModule } from 'ngx-ui-switch'; 
import { ChartsModule } from 'ng2-charts'; 
```

然后，将`UiSwitchModule`和`ChartsModule`添加到 imports 数组中：

```js
// snipp snipp 
imports: [ 
    RouterModule.forRoot(appRoutes), 
    BrowserModule, 
    BrowserAnimationsModule, 
    FormsModule, 
    HttpModule, 
    LocalStorageModule.withConfig({ 
      prefix: 'web-app', 
      storageType: 'localStorage' 
    }), 
    SimpleNotificationsModule.forRoot(), 
    UiSwitchModule, 
    ChartsModule 
  ], 
// snipp snipp 
```

完成后，我们需要将`chart.js`导入到我们的应用程序中。打开`web-app/.angular-cli.json`并更新`scripts`部分，如下所示：

```js
// snipp snipp  
"scripts": [ 
        "../node_modules/chart.js/dist/Chart.js" 
      ], 
// snipp snipp  
```

保存所有文件并重新启动 Web 应用程序，如果它已经在运行。

现在，我们可以在设备组件中使用这个指令。

在我们当前的用例中，我们需要显示温度和湿度值，并提供一个切换开关来打开/关闭 LED。为此，我们在`web-app/src/app/device/device.component.html`中的模板将如下所示：

```js
<div class="container"> 
    <br> 
    <div *ngIf="!device"> 
        <h3 class="text-center">Loading!</h3> 
    </div> 
    <div class="row" *ngIf="lastRecord"> 
        <div class="col-md-12"> 
            <div class="panel panel-info"> 
                <div class="panel-heading"> 
                    <h3 class="panel-title"> 
                        {{device.name}} 
                    </h3> 
                    <span class="pull-right btn-click"> 
                        <i class="fa fa-chevron-circle-up"></i> 
                    </span> 
                </div> 
                <div class="clearfix"></div> 
                <div class="table-responsive"> 
                    <table class="table table-striped"> 
                        <tr> 
                            <td>Toggle LED</td> 
                            <td> 
                                <ui-switch [(ngModel)]="toggleState" (change)="toggleChange($event)"></ui-switch> 
                            </td> 
                        </tr> 
                        <tr *ngIf="lastRecord"> 
                            <td>Temperature</td> 
                            <td>{{lastRecord.data.t}}</td> 
                        </tr> 
                        <tr *ngIf="lastRecord"> 
                            <td>Humidity</td> 
                            <td>{{lastRecord.data.h}}</td> 
                        </tr> 
                        <tr *ngIf="lastRecord"> 
                            <td>Received At</td> 
                            <td>{{lastRecord.createdAt | date: 'medium'}}</td> 
                        </tr> 
                    </table> 
                    <div class="col-md-10 col-md-offset-1" *ngIf="lineChartData.length > 0"> 
                        <canvas baseChart [datasets]="lineChartData" [labels]="lineChartLabels" [options]="lineChartOptions" [legend]="lineChartLegend" [chartType]="lineChartType"></canvas> 
                    </div> 
                </div> 
            </div> 
        </div> 
    </div> 
</div> 
```

`DeviceComponent`类的所需代码：`web-app/src/app/device/device.component.ts`将如下所示：

```js
import { Component, OnInit, OnDestroy } from '@angular/core'; 
import { DevicesService } from '../services/devices.service'; 
import { Params, ActivatedRoute } from '@angular/router'; 
import { SocketService } from '../services/socket.service'; 
import { DataService } from '../services/data.service'; 
import { NotificationsService } from 'angular2-notifications'; 

@Component({ 
   selector: 'app-device', 
   templateUrl: './device.component.html', 
   styleUrls: ['./device.component.css'] 
}) 
export class DeviceComponent implements OnInit, OnDestroy { 
   device: any; 
   data: Array<any>; 
   toggleState: boolean = false; 
   private subDevice: any; 
   private subData: any; 
   lastRecord: any; 

   // line chart config 
   public lineChartOptions: any = { 
         responsive: true, 
         legend: { 
               position: 'bottom', 
         }, hover: { 
               mode: 'label' 
         }, scales: { 
               xAxes: [{ 
                     display: true, 
                     scaleLabel: { 
                           display: true, 
                           labelString: 'Time' 
                     } 
               }], 
               yAxes: [{ 
                     display: true, 
                     ticks: { 
                           beginAtZero: true, 
                           steps: 10, 
                           stepValue: 5, 
                           max: 70 
                     } 
               }] 
         }, 
         title: { 
               display: true, 
               text: 'Temperature & Humidity vs. Time' 
         } 
   }; 
   public lineChartLegend: boolean = true; 
   public lineChartType: string = 'line'; 
   public lineChartData: Array<any> = []; 
   public lineChartLabels: Array<any> = []; 

   constructor(private deviceService: DevicesService, 
         private socketService: SocketService, 
         private dataService: DataService, 
         private route: ActivatedRoute, 
         private notificationsService: NotificationsService) { } 

   ngOnInit() { 
         this.subDevice = this.route.params.subscribe((params) => { 
               this.deviceService.getOne(params['id']).subscribe((response) => { 
                     this.device = response.json(); 
                     this.getData(); 
                     this.socketInit(); 
               }); 
         }); 
   } 

   getData() { 
         this.dataService.get(this.device.macAddress).subscribe((response) => { 
               this.data = response.json(); 
               this.genChart(); 
               this.lastRecord = this.data[0]; // descending order data 
               if (this.lastRecord) { 
                     this.toggleState = this.lastRecord.data.l; 
               } 
         }); 
   } 

   toggleChange(state) { 
         let data = { 
               macAddress: this.device.macAddress, 
               data: { 
                     t: this.lastRecord.data.t, 
                     h: this.lastRecord.data.h, 
                     l: state ? 1 : 0 
               }, 
               topic: 'led' 
         } 

         this.dataService.create(data).subscribe((resp) => { 
               if (resp.json()._id) { 
                     this.notificationsService.success('Device Notified!'); 
               } 
         }, (err) => { 
               console.log(err); 
               this.notificationsService.error('Device Notification Failed. Check console for the error!'); 
         }) 
   } 

   socketInit() { 
         this.subData = this.socketService.getData(this.device.macAddress).subscribe((data) => { 
               if(this.data.length <= 0) return; 
               this.data.splice(this.data.length - 1, 1); // remove the last record 
               this.data.push(data); // add the new one 
               this.lastRecord = data; 
               this.genChart(); 
         }); 
   } 

   ngOnDestroy() { 
         this.subDevice.unsubscribe(); 
         this.subData ? this.subData.unsubscribe() : ''; 
   } 

   genChart() { 

         let data = this.data; 
         let _dtArr: Array<any> = []; 
         let _lblArr: Array<any> = []; 

         let tmpArr: Array<any> = []; 
         let humArr: Array<any> = []; 

         for (var i = 0; i < data.length; i++) { 
               let _d = data[i]; 
               tmpArr.push(_d.data.t); 
               humArr.push(_d.data.h); 
               _lblArr.push(this.formatDate(_d.createdAt)); 
         } 

         // reverse data to show the latest on the right side 
         tmpArr.reverse(); 
         humArr.reverse(); 
         _lblArr.reverse(); 

         _dtArr = [ 
               { 
                     data: tmpArr, 
                     label: 'Temperature' 
               }, 
               { 
                     data: humArr, 
                     label: 'Humidity %' 
               }, 
         ] 

         this.lineChartData = _dtArr; 
         this.lineChartLabels = _lblArr; 
   } 

   private formatDate(originalTime) { 
         var d = new Date(originalTime); 
         var datestring = d.getDate() + "-" + (d.getMonth() + 1) + "-" + d.getFullYear() + " " + 
               d.getHours() + ":" + d.getMinutes(); 
         return datestring;
```

```js
   } 
} 
```

需要注意的关键方法如下：

+   `getData()`: 此方法用于在页面加载时获取最近的 30 条记录。我们从 API 引擎中以降序发送数据；因此我们提取最后一条记录并将其保存为最后一条记录。如果需要，我们可以使用剩余的记录来绘制图表

+   `toggleChange()`: 当切换开关被点击时，将触发此方法。此方法将发送数据到 API 引擎以保存

+   `socketInit()`: 此方法一直监听设备上的数据保存事件。使用此方法，我们将`lastRecord`变量更新为设备上的最新数据

+   `genChart()`: 此方法获取数据集合，然后绘制图表。当新数据通过套接字到达时，我们会从数据数组中删除最后一条记录并推送新记录，始终保持 30 条记录的总数

有了这个，我们就完成了处理此设置所需的模板开发。

保存所有文件，启动代理程序、API 引擎和 Web 应用程序，然后登录应用程序，然后导航到设备页面。

如果一切设置正确，我们应该看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00042.jpeg)

现在，每当数据通过套接字传输时，图表会自动更新！

现在，为了测试 LED，切换 LED 按钮到开启状态，您应该看到我们在树莓派上设置的 LED 会亮起，同样，如果我们关闭它，LED 也会关闭。

# 构建桌面应用程序并实现端到端流程

现在我们已经完成了与 Web 应用程序的端到端流程，我们将扩展到桌面和移动应用程序。我们将首先构建相同 API 引擎的桌面客户端。因此，如果用户更喜欢使用桌面应用程序而不是 Web 或移动应用程序，他/她可以使用这个。

这个桌面应用程序将具有与 Web 应用程序相同的所有功能。

为了构建桌面应用程序，我们将使用 electron ([`electron.atom.io/`](https://electron.atom.io/)) 框架。使用名为`generator-electron` ([`github.com/sindresorhus/generator-electron`](https://github.com/sindresorhus/generator-electron)) 的 Yeoman ([`yeoman.io/`](http://yeoman.io/)) 生成器，我们将创建基本应用程序。然后，我们将构建我们的 Web 应用程序，并使用该构建的`dist`文件夹作为桌面应用程序的输入。一旦我们开始工作，所有这些将更加清晰。

要开始，请运行以下命令：

```js
npm install yo generator-electron -g  
```

这将安装 yeoman 生成器和 electron 生成器。接下来，在`chapter2`文件夹内，创建一个名为`desktop-app`的文件夹，然后，在新的命令提示符/终端中运行以下命令：

```js
yo electron
```

这个向导将询问一些问题，您可以相应地回答：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00043.jpeg)

这将安装所需的依赖项。安装完成后，我们应该看到以下文件夹结构：

```js
.

├── index.css

├── index.html

├── index.js

├── license

├── package.json

└── readme.md
```

有了根目录下的`node_modules`文件夹。

一切都始于`desktop-app/package.json`的启动脚本，它启动`desktop-app/index.js`。`desktop-app/index.js`创建一个新的浏览器窗口，并启动`desktop-app/index.html`页面。

要从`desktop-app`文件夹内快速测试驱动，请运行以下命令：

```js
npm start   
```

因此，我们应该看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00044.jpeg)

现在，我们将添加所需的代码。在`desktop-app`文件夹的根目录下，创建一个名为`freeport.js`的文件，并更新`desktop-app/freeport.js`如下：

```js
var net = require('net') 
module.exports = function(cb) { 
    var server = net.createServer(), 
        port = 0; 
    server.on('listening', function() { 
        port = server.address().port 
        server.close() 
    }); 
    server.on('close', function() { 
        cb(null, port) 
    }) 
    server.on('error', function(err) { 
        cb(err, null) 
    }) 
    server.listen(0, '127.0.0.1') 
} 
```

使用上述代码，我们将在最终用户的计算机上找到一个空闲端口，并在 electron 外壳中启动我们的 Web 应用程序。

接下来，在`desktop-app`文件夹的根目录下创建一个名为`app`的文件夹。我们将在这里倾倒文件。接下来，在`desktop-app`文件夹的根目录下，创建一个名为`server.js`的文件。更新`server.js`如下：

```js
var FreePort = require('./freeport.js'); 
var http = require('http'), 
    fs = require('fs'), 
    html = ''; 

module.exports = function(cb) { 
    FreePort(function(err, port) { 
        console.log(port); 
        http.createServer(function(request, response) { 
            if (request.url === '/') { 
                html = fs.readFileSync('./app/index.html'); 
            } else { 
                html = fs.readFileSync('./app' + request.url); 
            } 
            response.writeHeader(200, { "Content-Type": "text/html" }); 
            response.write(html); 
            response.end(); 
        }).listen(port); 
        cb(port); 
    }); 
} 
```

在这里，我们监听一个空闲端口并启动`index.html`。现在，我们需要做的就是更新`desktop-app/index.js`中的`createMainWindow()`如下：

```js
// snipp snipp 
function createMainWindow() { 
    const { width, height } = electron.screen.getPrimaryDisplay().workAreaSize; 
    const win = new electron.BrowserWindow({ width, height }) 
    const server = require("./server")(function(port) { 
        win.loadURL('http://localhost:' + port); 
        win.on('closed', onClosed); 
        console.log('Desktop app started on port :', port); 
    }); 

    return win; 
} 
// snipp snipp 
```

这就是我们需要的所有设置。

现在，返回到`web-app`文件夹的终端/提示符（是的`web-app`，而不是`desktop-app`），并运行以下命令：

```js
ng build --env=prod
```

这将在`web app`文件夹内创建一个名为`dist`的新文件夹。`dist`文件夹的内容应如下所示：

```js
.

├── favicon.ico

├── index.html

├── inline.bundle.js

├── inline.bundle.js.map

├── main.bundle.js

├── main.bundle.js.map

├── polyfills.bundle.js

├── polyfills.bundle.js.map

├── scripts.bundle.js

├── scripts.bundle.js.map

├── styles.bundle.js

├── styles.bundle.js.map

├── vendor.bundle.js

└── vendor.bundle.js.map
```

我们在 web 应用程序中编写的所有代码最终都打包到了前述文件中。我们将获取`dist`文件夹内的所有文件（而不是`dist`文件夹），然后将其粘贴到`desktop-app/app`文件夹中。在进行前述更改后，桌面应用程序的最终结构将如下所示：

```js
.

├── app

│ ├── favicon.ico

│ ├── index.html

│ ├── inline.bundle.js

│ ├── inline.bundle.js.map

│ ├── main.bundle.js

│ ├── main.bundle.js.map

│ ├── polyfills.bundle.js

│ ├── polyfills.bundle.js.map

│ ├── scripts.bundle.js

│ ├── scripts.bundle.js.map

│ ├── styles.bundle.js

│ ├── styles.bundle.js.map

│ ├── vendor.bundle.js

│ └── vendor.bundle.js.map

├── freeport.js

├── index.css

├── index.html

├── index.js

├── license

├── package.json

├── readme.md

└── server.js
```

从现在开始，我们只需将`web-app/dist`文件夹的内容粘贴到`desktop-app`的`app`文件夹中。

要进行测试，请运行以下命令：

```js
npm start 
```

这将带来登录屏幕，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00045.jpeg)

如果您看到之前显示的弹出窗口，请允许。成功登录后，您应该能够看到您帐户中的所有设备，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00046.jpeg)

最后，设备信息屏幕：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00047.jpeg)

现在我们可以打开/关闭 LED，它应该有相应的反应。

现在，我们已经完成了桌面应用程序。

在下一节中，我们将使用 Ionic 框架构建一个移动应用程序。

# 构建移动应用程序并实现端到端流程

在本节中，我们将使用 Ionic 框架（[`ionicframework.com/`](http://ionicframework.com/)）构建我们的移动伴侣应用程序。输出或示例与我们为 web 和桌面应用程序所做的相同。

开始时，我们将通过运行以下命令安装最新版本的`ionic`和`cordova`：

```js
npm install -g ionic cordova  
```

现在，我们需要移动应用程序基础。如果您还没有克隆该书的代码存储库，可以使用以下命令（在您的任何位置）进行克隆：

```js
git clone git@github.com:PacktPublishing/Practical-Internet-of-Things-with-JavaScript.git
```

或者您也可以从[`github.com/PacktPublishing/Practical-Internet-of-Things-with-JavaScript`](https://github.com/PacktPublishing/Practical-Internet-of-Things-with-JavaScript)下载 zip 文件。

一旦存储库被下载，`cd`进入`base`文件夹，并将`mobile-app-base`文件夹复制到`chapter2`文件夹中。

复制完成后，`cd`进入`mobile-app`文件夹并运行以下命令：

```js
npm install
```

然后

```js
ionic cordova platform add android 
```

或者

```js
 ionic cordova platform add ios 
```

这将负责安装所需的依赖项并添加 Android 或 iOS 平台。

如果我们查看`mobile-app`文件夹，应该会看到以下内容：

```js
.

├── README.md

├── config.xml

├── hooks

│ └── README.md

├── ionic.config.json

├── package.json

├── platforms

│ ├── android

│ └── platforms.json

├── plugins

│ ├── android.json

│ ├── cordova-plugin-console

│ ├── cordova-plugin-device

│ ├── cordova-plugin-splashscreen

│ ├── cordova-plugin-statusbar

│ ├── cordova-plugin-whitelist

│ ├── fetch.json

│ └── ionic-plugin-keyboard

├── resources

│ ├── android

│ ├── icon.png

│ ├── ios

│ └── splash.png

├── src

│ ├── app

│ ├── assets

│ ├── declarations.d.ts

│ ├── index.html

│ ├── manifest.json

│ ├── pages

│ ├── service-worker.js

│ ├── services

│ └── theme

├── tsconfig.json

├── tslint.json

└── www

├── assets

├── build

├── index.html

├── manifest.json

└── service-worker.js
```

在我们的`mobile-app`文件夹中，最重要的文件是`mobile-app/config.xml`。该文件包含了 cordova 需要将 HTML/CSS/JS 应用程序转换为混合移动应用程序所需的定义。

接下来，我们有`mobile-app/resources`、`mobile-app/plugins`和`mobile-app/platforms`文件夹，其中包含我们正在开发的应用程序的 cordova 封装代码。

最后，`mobile-app/src`文件夹，这个文件夹是我们所有源代码的所在地。移动端的设置与我们为 web 应用程序和桌面应用程序所做的设置类似。我们有一个服务文件夹，其中包括`mobile-app/src/services/auth.service.ts`用于身份验证，`mobile-app/src/services/device.service.ts`用于与设备 API 进行交互，`mobile-app/src/services/data.service.ts`用于从设备获取最新数据，`mobile-app/src/services/socket.service.ts`用于在我们的移动应用程序中设置 Web 套接字，最后，`mobile-app/src/services/toast.service.ts`用于显示适用于移动设备的通知。`mobile-app/src/services/toast.service.ts`类似于我们在 web 和桌面应用程序中使用的通知服务。

接下来，我们有所需的页面。移动应用程序只实现了登录页面。我们强制用户使用 Web 或桌面应用程序来创建新帐户。`mobile-app/src/pages/login/login.ts`包括身份验证逻辑。`mobile-app/src/pages/home/home.ts`包括用户注册的所有设备列表。`mobile-app/src/pages/add-device/add-device.ts`具有添加新设备所需的逻辑，`mobile-app/src/pages/view-device/view-device.ts`用于查看设备信息。

现在，在`mobile-app`文件夹中，运行以下命令：

```js
ionic serve  
```

这将在浏览器中启动应用程序。如果您想在实际应用程序上进行测试，可以运行以下命令：

```js
ionic cordova run android   
```

或者，您可以运行以下命令：

```js
ionic cordova run ios  
```

这将在设备上启动应用程序。在任何情况下，应用程序的行为都将相同。

应用程序启动后，我们将看到登录页面：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00048.jpeg)

一旦我们成功登录，我们应该看到如下的主页。我们可以使用标题栏中的+图标添加新设备：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00049.jpeg)

新创建的设备应该在我们的主屏幕上反映出来，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00050.jpeg)

如果我们点击“查看设备”，我们应该看到设备信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00051.jpeg)

当我们切换按钮开/关时，树莓派上的 LED 应该打开/关闭：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00052.jpeg)

同一设置的另一个视图如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00053.jpeg)

上述是使用 DHT11 传感器和 LED 设置的树莓派 3 的设置。

通过这样做，我们已经成功建立了一个端到端的架构，用于执行物联网示例。从现在开始，我们将与 Web 应用程序、移动应用程序、桌面应用程序、树莓派以及一些 API 引擎一起工作，用于我们接下来的示例。我们将进行最小的更改。我们将专注于用例，而不是一遍又一遍地构建设置。

# 故障排除

如果您没有看到预期的输出，请检查以下内容：

+   检查经纪人、API 引擎、Web 应用程序和树莓派应用程序是否正在运行

+   检查提供给树莓派的经纪人的 IP 地址

+   检查提供给移动应用程序的 API 引擎的 IP 地址

# 摘要

在第二章，*IoTFW.js - I*和在本章中，我们经历了设置整个框架以与物联网解决方案一起工作的整个过程。我们只使用 JavaScript 作为编程语言构建了整个框架。

我们从理解架构和数据流开始，从树莓派到最终用户设备，如 Web 应用程序、桌面应用程序或移动应用程序。然后我们开始使用 Mosca 设置经纪人，设置 MongoDB 后。接下来，我们设计并开发了 API 引擎，并完成了基本的树莓派设置。

我们在 Web 应用程序和桌面应用程序上工作，并将简单的 LED 和 DHT11 温湿度传感器与树莓派集成，并看到了从一端到另一端的简单流程。我们将温度和湿度实时传输到 Web 应用程序和桌面应用程序，并使用切换按钮打开了 LED。

最后，我们建立了一个移动应用程序，并实现/验证了 LED 和 DHT11 的设置。

在第四章，*智能农业*，使用当前设置作为基础，我们将构建智能农业解决方案。
