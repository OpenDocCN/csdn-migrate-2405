# C# 和 Unity 2021 游戏开发学习手册（五）

> 原文：[`zh.annas-archive.org/md5/D5230158773728FED97C67760D6D7EA0`](https://zh.annas-archive.org/md5/D5230158773728FED97C67760D6D7EA0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：旅程继续

如果你作为一个完全的编程新手开始阅读这本书，恭喜你的成就！如果你对 Unity 或其他脚本语言有一些了解，猜猜看？恭喜你。如果你开始时对我们已经涵盖的所有主题和概念都有牢固的理解，你猜对了：恭喜你。没有什么学习经历是微不足道的，无论你认为自己学到了多少或多少。享受你花在学习新东西上的时间，即使最终只是学到了一个新的关键词。

当你到达这段旅程的尽头时，重温你一路学到的技能是很重要的。就像所有的教学内容一样，总是有更多的东西可以学习和探索，所以这一章将专注于巩固以下主题，并为你的下一个冒险提供资源：

+   深入挖掘

+   面向对象编程及更多

+   设计模式

+   接近 Unity 项目

+   C#和 Unity 资源

+   Unity 认证

+   下一步和未来学习

# 深入挖掘

虽然我们在这本书中做了大量关于变量、类型、方法和类的工作，但仍有一些 C#的领域没有被探索。

学习新技能不应该是简单的信息轰炸，而是应该是一个谨慎的积木堆叠，每一块积木都建立在已经获得的基础知识之上。

以下是你在使用 C#进行编程旅程中需要深入了解的一些概念，无论是在 Unity 中还是其他脚本语言中：

+   可选和动态变量

+   调试方法

+   并发编程

+   网络和 RESTful API

+   递归和反射

+   设计模式

+   LINQ

+   函数式编程

当你重新审视我们在这本书中编写的代码时，不要只考虑我们取得了什么成就，还要考虑我们项目的不同部分是如何协同工作的。我们的代码是模块化的，意味着行为和逻辑是自包含的。我们的代码是灵活的，因为我们使用了面向对象编程（OOP）技术，这使得改进和更新变得容易。我们的代码是干净的，不重复，这使得任何查看它的人都能轻松阅读，即使是我们自己。

这里的要点是消化基本概念需要时间。事情并不总是一次就能理解，而且“啊哈！”的时刻也不总是在你期待的时候出现。关键是要不断学习新东西，但始终牢记你的基础。

让我们听从自己的建议，在下一节重新审视面向对象编程的原则。

# 回顾你的面向对象编程

面向对象编程是一个广阔的专业领域，它的掌握不仅需要学习，还需要花时间将其原则应用到现实软件开发中。

通过这本书学到的所有基础知识，可能会让你觉得这是一座你最好根本不要尝试攀登的山。然而，当你感到这样的时候，退一步重新审视这些概念：

+   类是你想在代码中创建的对象的蓝图

+   它们可以包含属性、方法和事件

+   它们使用构造函数来定义它们如何被实例化

+   从类蓝图实例化对象会创建该类的唯一实例

+   类是引用类型，这意味着当引用被复制时，它不是一个新的实例

+   结构体是值类型，这意味着当结构体被复制时，会创建一个全新的实例

+   类可以使用继承与子类共享公共行为和数据

+   类使用访问修饰符来封装它们的数据和行为

+   类可以由其他类或结构类型组成

+   多态性允许子类被视为其父类

+   多态性也允许改变子类的行为而不影响父类

一旦掌握了面向对象编程，就可以探索其他编程范式，如函数式和响应式编程。简单的在线搜索将让你朝着正确的方向前进。

# 设计模式入门

在我们结束本书之前，我想谈谈一个将在你的编程生涯中扮演重要角色的概念：**设计模式**。搜索设计模式或软件编程模式将给你提供大量的定义和示例，如果你以前从未遇到过它们，可能会让你感到不知所措。让我们简化这个术语，并定义设计模式如下：

解决编程问题或在任何应用程序开发过程中经常遇到的情况的模板。这些不是硬编码的解决方案——它们更像是经过测试的指导方针和最佳实践，可以适应特定情况。

设计模式成为编程词汇的重要部分背后有着悠久的历史，但挖掘这一点取决于你自己。

如果这个概念触动了你的编程思维，可以从书籍*设计模式：可复用面向对象软件的元素*和其作者*四人组*：Erich Gamma、Richard Helm、Ralph Johnson 和 John Vlissides 开始。

这只是设计模式在现实世界编程情况下所能做的冰山一角。我强烈鼓励你深入了解它们的历史和应用——它们将是你未来的最佳资源之一。

接下来，即使本书的目标是教你 C#，我们也不能忘记我们学到的关于 Unity 的一切。

# 接近 Unity 项目

即使 Unity 是一个 3D 游戏引擎，它仍然必须遵循构建在其上的代码所制定的原则。当你考虑你的游戏时，请记住屏幕上看到的 GameObject、组件和系统只是类和数据的可视化表示；它们并不神奇或未知——它们是将你在本书中学到的编程基础知识发展到高级结论的结果。

Unity 中的一切都是对象，但这并不意味着所有的 C#类都必须在引擎的`MonoBehaviour`框架内工作。不要局限于只考虑游戏内机制；拓展思路，根据项目的需要定义数据或行为。

最后，始终要问自己如何将代码最好地分离成功能块，而不是创建庞大、臃肿、千行代码的类。相关的代码应该负责其行为并一起存储。这意味着创建单独的`MonoBehaviour`类并将它们附加到受其影响的 GameObject 上。我在本书开头就说过，我会再次重申：编程更多是一种心态和语境框架，而不是语法记忆。继续训练你的大脑像程序员一样思考，最终，你将无法以其他方式看待世界。

# 我们没有涵盖的 Unity 功能

我们在*第六章*《与 Unity 一起动手》中简要介绍了许多 Unity 的核心功能，但引擎还有很多其他功能。这些主题并不按重要性顺序排列，但如果你要继续使用 Unity 开发，你至少应该对以下内容有所了解：

+   着色器和特效

+   可编程对象

+   编辑器扩展脚本

+   非编程 UI

+   ProBuilder 和地形工具

+   PlayerPrefs 和数据保存

+   模型绑定

+   动画师状态和转换

你还应该回过头去深入了解编辑器中的照明、导航、粒子效果和动画功能。

# 下一步

现在您已经具备了 C#语言的基本读写能力，您可以寻求额外的技能和语法。这通常以在线社区、教程网站和 YouTube 视频的形式出现，但也可以包括教科书，比如这本书。从读者转变为软件开发社区的积极成员可能很困难，尤其是在众多选择的情况下，因此我列出了一些我最喜欢的 C#和 Unity 资源，以帮助您入门。

## C#资源

在我用 C#开发游戏或应用程序时，我总是把微软文档打开在一个我可以轻松访问的窗口中。如果我找不到特定问题或问题的答案，我会开始查看我经常使用的社区网站：

+   C# Corner: [`www.c-sharpcorner.com`](https://www.c-sharpcorner.com)

+   Dot Net Perls: [`www.dotnetperls.com`](http://www.dotnetperls.com)

+   Stack Overflow: [`stackoverflow.com`](https://stackoverflow.com)

由于我大部分的 C#问题都与 Unity 有关，我倾向于使用这类资源，我已经在下一节中列出了这些资源。

## Unity 资源

最好的 Unity 学习资源来自于视频教程、文章、免费资产和文档，都可以在[`unity3d.com`](https://unity3d.com)找到。

但是，如果您正在寻找社区答案或特定的编程问题解决方案，请访问以下网站：

+   Unity Forum: [`forum.unity.com`](https://forum.unity.com)

+   Unity Learn: [`learn.unity.com`](https://learn.unity.com)

+   Unity Answers: [`answers.unity.com`](https://answers.unity.com)

+   Unity Discord 频道：[`discord.com/invite/unity`](https://discord.com/invite/unity)

+   Stack Overflow: [`stackoverflow.com`](https://stackoverflow.com)

如果您更喜欢视频教程，YouTube 上也有一个庞大的视频教程社区；以下是我的前五个：

+   Brackeys: [`www.youtube.com/user/Brackeys`](https://www.youtube.com/user/Brackeys)

+   Sykoo: [`www.youtube.com/user/SykooTV/videos`](https://www.youtube.com/user/SykooTV/videos)

+   Renaissance Coders: [`www.youtube.com/channel/UCkUIs-k38aDaImZq2Fgsyjw`](https://www.youtube.com/channel/UCkUIs-k38aDaImZq2Fgsyjw)

+   BurgZerg Arcade: [`www.youtube.com/user/BurgZergArcade`](https://www.youtube.com/user/BurgZergArcade)

Packt 图书馆还有大量关于 Unity、游戏开发和 C#的书籍和视频，可以在[`www.packtpub.com/all-products`](https://www.packtpub.com/all-products)找到。

## Unity 认证

Unity 现在为程序员和艺术家提供各种级别的认证，这将为您的简历增添一定的可信度和经验技能排名。如果您试图以自学或非计算机科学专业的身份进入游戏行业，这些认证非常有用，它们有以下几种类型：

+   认证助理

+   认证用户：程序员

+   认证程序员

+   认证艺术家

+   认证专家-游戏程序员

+   认证专家-技术艺术家：绑定和动画

+   认证专家-技术艺术家：着色和特效

Unity 还提供内部和通过第三方提供者提供的预备课程，以帮助您为各种认证做好准备。您可以在[`certification.unity.com`](https://certification.unity.com)找到所有信息。

永远不要让认证，或者缺乏认证，定义您的工作或您发布到世界上的东西。您最后的英雄试炼是加入开发社区，并开始留下您的印记。

# 英雄试炼-将某物发布到世界上

我在这本书中给你的最后一个任务可能是最难的，但也是最有回报的。您的任务是利用您的 C#和 Unity 知识，创建一些内容并发布到软件或游戏开发社区中。无论是一个小的游戏原型还是一个大型的手机游戏，以以下方式将您的代码发布出去：

+   加入 GitHub（[`github.com`](https://github.com)）

+   在 Stack Overflow、Unity Answers 和 Unity 论坛上积极参与

+   注册在 Unity Asset Store 上发布自定义资产（[`assetstore.unity.com`](https://assetstore.unity.com)）

无论你的激情项目是什么，都要让它走向世界。

# 摘要

你可能会觉得这标志着你的编程之旅的结束，但你错了。学习永无止境，只有一个开始。我们开始理解编程的基本构建块，C#语言的基础知识，以及如何将这些知识转化为 Unity 中有意义的行为。如果你已经到了这最后一页，我相信你已经实现了这些目标，你也应该这样认为。

当我刚开始时，我希望有人告诉我一句话：如果你说你是程序员，那么你就是程序员。社区中会有很多人告诉你，你是业余的，你缺乏被认为是“真正”的程序员所需的经验，或者更好的是，你需要某种无形的专业认可。这是错误的：如果你经常练习像程序员一样思考，努力用高效和干净的代码解决问题，并且热爱学习新事物，那么你就是程序员。拥有这个身份；这将使你的旅程变得非常刺激。

# 加入我们的 Discord！

与其他用户、Unity/C#专家和 Harrison Ferrone 一起阅读本书。提出问题，为其他读者提供解决方案，通过*问我任何事*与作者交流，以及更多。

立即加入！

[`packt.link/csharpunity2021`](https://packt.link/csharpunity2021)

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/QR_Code_9781801813945.png)


# 第十五章：快速测验答案

# 第一章-了解您的环境

## 快速测验-处理脚本

| Q1 | Unity 和 Visual Studio 有一种共生关系 |
| --- | --- |
| Q2 | 参考手册 |
| Q3 | 没有，因为它是一个参考文档，而不是一个测试 |
| Q4 | 当新文件以编辑模式出现在**项目**选项卡中时，将使类名与文件名相同，并防止命名冲突 |

# 第二章-编程的基本构件

## 快速测验-C#构建模块

| Q1 | 存储特定类型的数据以供 C#文件中的其他地方使用 |
| --- | --- |
| Q2 | 方法存储可执行的代码行，以便快速高效地重用 |
| Q3 | 通过将`MonoBehaviour`作为其父类并将其附加到 GameObject 来实现 |
| Q4 | 访问组件或附加到不同 GameObject 的文件的变量和方法 |

# 第三章-深入变量、类型和方法

## 快速测验#1-变量和方法

| Q1 | 使用驼峰命名法 |
| --- | --- |
| Q2 | 将变量声明为`public` |
| Q3 | `public`、`private`、`protected`和`internal` |
| Q4 | 当隐式转换不存在时 |
| Q5 | 从方法返回的数据类型，带括号的方法名称，以及代码块的一对大括号 |
| Q6 | 允许将参数数据传递到代码块中 |
| Q7 | 该方法不会返回任何数据 |
| Q8 | `Update()`方法在每一帧都会被调用 |

# 第四章-控制流和集合类型

## 快速测验#1-如果、而且、或者

| Q1 | 真或假 |
| --- | --- |
| Q2 | 用感叹号符号（`!`）写的 NOT 运算符 |
| Q3 | 与双和符号（`&&`）写的 AND 运算符 |
| Q4 | 用双竖线（` | | `）写的 OR 运算符 |

## 快速测验#2-关于集合的一切

| Q1 | 数据存储的位置 |
| --- | --- |
| Q2 | 数组或列表中的第一个元素是 0，因为它们都是从零开始索引的 |
| Q3 | 不是-当数组或列表声明时，定义了它存储的数据类型，使得元素不可能是不同类型的 |
| Q4 | 一旦初始化，数组就无法动态扩展，这就是为什么列表是更灵活的选择，因为它们可以动态修改 |

# 第五章-使用类、结构和面向对象编程

## 快速测验-所有关于 OOP 的事情

| Q1 | 构造函数 |
| --- | --- |
| Q2 | 通过复制，而不是像类一样通过引用 |
| Q3 | 封装、继承、组合和多态 |
| Q4 | `GetComponent` |

# 第六章-开始使用 Unity

## 快速测验-基本 Unity 功能

| Q1 | 原语 |
| --- | --- |
| Q2 | *z*轴 |
| Q3 | 将 GameObject 拖入`Prefabs`文件夹中 |
| Q4 | 关键帧 |

# 第七章-运动、摄像机控制和碰撞

## 快速测验-玩家控制和物理

| Q1 | `Vector3` |
| --- | --- |
| Q2 | `InputManager` |
| Q3 | `Rigidbody`组件 |
| Q4 | `FixedUpdate` |

# 第八章-脚本游戏机制

## 快速测验-处理机制

| Q1 | 一组或一系列属于同一变量的命名常量 |
| --- | --- |
| Q2 | 使用`Instantiate()`方法与现有的 Prefab |
| Q3 | `get`和`set`访问器 |
| Q4 | `OnGUI()` |

# 第九章-基本 AI 和敌人行为

## 快速测验-AI 和导航

| Q1 | 它是从级别几何体自动生成的 |
| --- | --- |
| Q2 | `NavMeshAgent` |
| Q3 | 过程式编程 |
| Q4 | 不要重复自己 |

# 第十章-重新审视类型、方法和类

## 快速测验-升级

| Q1 | `Readonly` |
| --- | --- |
| Q2 | 更改方法参数的数量或它们的参数类型 |
| Q3 | 接口不能有方法实现或存储变量 |
| Q4 | 创建类型别名以区分冲突的命名空间 |

# 第十一章-介绍堆栈、队列和哈希集

## 快速测验-中级集合

| Q1 | 堆栈 |
| --- | --- |
| Q2 | 窥视 |
| Q3 | 是 |
| Q4 | `ExceptWith` |

# 第十二章-保存、加载和序列化数据

## 快速测验-数据管理

| Q1 | `System.IO`命名空间 |
| --- | --- |
| Q2 | `Application.persistentDataPath` |
| Q3 | 流以字节形式读取和写入数据 |
| Q4 | 整个 C#类对象被转换为 JSON 格式 |

# 第十三章 - 探索泛型，委托等等

## 中级 C#知识问答

| Q1 | 泛型类需要有一个定义的类型参数 |
| --- | --- |
| Q2 | `values` 方法和 `delegates` 方法签名 |
| Q3 | `-=` 运算符 |
| Q4 | `throw` 关键字 |

# 加入我们的 Discord！

与其他用户一起阅读本书，与 Unity/C#专家和 Harrison Ferrone 一起阅读，提问，为其他读者提供解决方案，通过*问我任何事*与作者交流等等。

立即加入！

[`packt.link/csharpunity2021`](https://packt.link/csharpunity2021)

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/QR_Code_9781801813945.png)
