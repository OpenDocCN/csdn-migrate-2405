# Vue2 Bootstrap4 Web 开发（二）

> 原文：[`zh.annas-archive.org/md5/7E556BCDBA065D692175F778ABE043D8`](https://zh.annas-archive.org/md5/7E556BCDBA065D692175F778ABE043D8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：让我们开始吧

在上一章中，我们讨论了本书中将使用的三种主要技术，以构建我们的应用程序。我们深入探讨了 Vue.js 的许多内容；我们介绍了 Bootstrap 的一些功能，并检查了使用 Google Firebase 控制台可以实现什么。我们知道如何使用 Vue.js 从头开始创建应用程序。我们知道如何在 Bootstrap 的帮助下使其美观，也知道如何使用 Google Firebase 将其部署到实时环境中！这意味着我们已经百分之百准备好开始开发我们的应用程序了！

编写应用程序是一个有趣、具有挑战性和令人兴奋的过程……只要我们知道我们要编写什么，对吧？为了知道我们将要编写什么，我们必须定义应用程序的概念、其要求和目标用户。在本书中，我们不会完全涉及设计构建的整个过程，因为对此，您有很多其他书籍，因为这是一个大科学。

在本书中，特别是在本章中，在进行实施之前，我们至少会定义一组角色和用户故事。因此，在本章中，我们将执行以下操作：

+   阐述我们将用应用程序解决的问题

+   定义一些角色和用户故事

+   从用户故事中提取名词和动词

+   绘制将定义我们应用程序的主要屏幕和区域的模拟图

# 陈述问题

世界上有许多时间管理技术。一些大师和专业人士已经就如何有效管理时间，以便您高效并且所有的 KPI 值都高于任何可能的生产力基准进行了大量演讲。其中一些演讲真的很棒。当涉及到时间管理演讲时，我总是建议观看 Randy Pausch 在[`youtu.be/oTugjssqOT0`](https://youtu.be/oTugjssqOT0)上的演讲。

说到时间管理技术，有一种我特别喜欢的流行技术，我觉得非常简单易用。它被称为番茄钟（[`en.wikipedia.org/wiki/Pomodoro_Technique`](https://en.wikipedia.org/wiki/Pomodoro_Technique)）。这种技术包括以下原则：

+   在一定时间内工作，没有任何干扰。这段时间可以是 20 到 25 分钟，被称为番茄钟

+   在工作的番茄钟后，您有 5 分钟的休息时间。在这个休息时间里，您可以做任何您想做的事情——查看电子邮件、社交网络等等

+   在完成四个番茄钟后，你有权享受一个持续 10 到 15 分钟的较长休息时间。

番茄钟有许多实现方式。其中一些允许你配置工作番茄钟和短暂和长暂休息的时间。有些在工作番茄钟期间阻止社交网络页面；有些会发出噪音。在《学习 Vue.js 2》一书中，我们还构建了一个简单的番茄钟，它在工作期间发出棕色噪音，并在短暂休息期间显示随机小猫。

如果你正在阅读这本书，那么很可能你是一名开发人员，你一天中的大部分时间都是坐着，或者可能是站着，因为站立式办公桌如今非常流行。你在工作日（或夜晚）中改变姿势的频率有多高？你是否有背部问题？你去健身房吗？你喜欢慢跑吗？你多久在家锻炼一次？作为一名开发人员需要高度集中注意力，我们很容易忘记一点关于自己的事情。

在这本书中，我们将再次构建一个番茄钟。这次，它不仅会尝试解决时间管理问题，还会解决健身管理问题。它不会让你在休息期间做任何你想做的事情或者显示一些随机小猫，而是会告诉你做简单的锻炼。锻炼的种类从非常简单的头部旋转练习到俯卧撑和弹跳。用户可以根据他们所在办公室的类型选择一组自己喜欢的锻炼。用户还可以添加新的锻炼。锻炼也可以被评分。

因此，我们将实现的番茄钟的主要原则如下：

+   不间断地工作。专注于你正在做的事情。

+   在休息期间进行锻炼。

+   合作并添加新的令人兴奋的锻炼，可以被你和应用程序的其他用户使用。

# 需求收集

现在我们知道要构建什么，让我们为应用程序定义一系列要求。该应用程序主要用于显示计时器和展示锻炼。因此，让我们定义它必须具备的功能。以下是我的功能要求列表：

+   该应用程序应该显示倒计时计时器。

+   倒计时计时器可以从 25 到 0 分钟，从 5 到 0 分钟，或者从 10 到 0 分钟。

+   在应用程序的任何时刻都可以启动、暂停和停止倒计时计时器。

+   当时间到达 0 并且下一个休息时间或工作番茄开始时，应用程序应该发出一些声音。

+   该应用程序应该在短暂和长时间休息期间显示一个锻炼项目。可以跳过当前的锻炼项目并切换到下一个。也可以在休息期间完全跳过锻炼项目，只是盯着小猫。也可以标记给定的锻炼项目为已完成。

+   该应用程序必须提供认证机制。经过认证的用户可以配置番茄定时器，向系统添加新的锻炼项目，并查看他们的统计数据。

+   认证用户的统计数据显示每天、每周和每月完成的锻炼项目数量。

+   经过认证的用户可以配置番茄工作法定时器，如下所示：

+   为长时间工作的番茄定时器选择一个在 15 到 30 之间的值

+   为短暂休息定时器选择一个在 5 到 10 之间的值

+   为长休息定时器选择一个在 10 到 15 之间的值

+   经过认证的用户可以配置他们喜欢的锻炼项目集进行显示。

+   经过认证的用户可以创建新的锻炼项目并将其添加到系统中。

+   每个锻炼项目包括四个部分：标题、描述、图片和评分。

我还有一个非功能需求的基本清单，包括两个项目：

+   该应用程序应该使用持久存储来存储其数据——在我们的情况下是 Firebase 的实时数据库

+   该应用程序应该是响应式的，并且可以在多个平台和设备上运行

我想这已经足够支持我们的番茄工作法的功能了。或者，既然涉及健身，也许我们可以称之为 PoFIToro？或者，也许，既然我们的身体得到了一些好处，让我们称之为*ProFitOro*。

# 人物角色

通常，在开发应用程序之前，我们必须定义其目标用户。为此，我们要与应用程序的潜在用户进行多次问卷调查。问卷调查通常包括关于用户个人数据的问题，如年龄、性别等。还应该有关于用户使用模式的问题——操作系统、桌面或移动设备等。当然，还应该有关于应用程序本身的问题。例如，对于 ProFitOro 应用程序，我们可以问以下问题：

+   你每天在办公室花费多少小时？

+   你在工作日里在办公室坐多久？

+   你多久进行一次像慢跑、健身锻炼等体育活动？

+   你是在办公室工作还是在家工作？

+   你的工作场所有没有可以做俯卧撑的地方？

+   你有背部问题吗？

收集完所有问卷后，用户根据相似的模式和个人数据被分成不同的类别。然后，每个用户的类别形成一个单一的角色。我将在这里为 ProFitOro 应用程序留下四个角色。

让我们从一个叫做 Alex Bright 的虚构角色开始：

*Alex Bright*

**年龄**：32 岁

**性别**：男性

**教育**：硕士

**职业**：软件工程师，全职

**使用模式**：在办公室工作，使用运行 Ubuntu 的笔记本电脑和 iPhone。

**最喜欢的浏览器**：Google Chrome

**健康和健身**：每个月跑 5 公里。偶尔感到背部疼痛

让我们继续我们下一个虚构的角色—Anna Kuznetsova。

*Anna Kuznetsova*

**年龄**：22 岁

**性别**：女性

**教育**：学士学位

**职业**：学生

**使用模式**：大部分时间在家使用运行 Windows 的台式机和安卓手机。

**最喜欢的浏览器**：Mozilla Firefox

**健康和健身**：每周去健身房三次。没有任何健康问题

在写这本书的时候，我的一个朋友刚刚来我们家做客。他叫 Duarte，但我们取笑他叫 Dwart。他一露面，下一个角色就诞生了（请注意，我们的朋友 Duarte 离 45 岁还很远）：

*Dwart Azevedo*

**年龄**：45 岁

**性别**：男性

**教育**：博士

**职业**：副总工程师，全职

**使用模式**：在办公室工作，经常在共享工作空间和家里工作。使用 MacBook Pro 和 iPhone，并且在工作时花费大量时间坐着。

**健康和健身**：定期在家做锻炼。有时感到背部疼痛。

我丈夫 Rui 在一家名为 Gymondo 的在线健身公司工作。那里有一个名叫 Steve 的出色健身教练。他会把你推到极限。每次我和这个家伙一起做锻炼，之后我甚至都无法走路。这就是下一个角色诞生的原因：

*Steve Wilson*

**年龄**：35 岁

**性别**：男性

**职业**：健身教练，全职

**使用模式**：家里的 Windows 台式机

**健康和健身**：从不感到疼痛，每天每小时都训练

我们可以看到，我们的用户共同之处在于他们都花了一些时间保持相同的姿势（坐着），他们的工作需要一些专注力和可能需要时间管理技巧，他们有时需要改变姿势以防止背部问题。

# 用户故事

在定义了我们的用户之后，让我们写一些用户故事。当涉及编写用户故事时，我只需闭上眼睛，想象自己是这个人。让我们从德瓦特·阿塞韦多开始尝试这种心灵锻炼：

德瓦特·阿塞韦多

德瓦特的工作日包括会议、电话、视频会议和文书工作。今天，他非常忙碌，有访谈和会议。最后，他有几个小时可以处理整整一周等待他的文书工作。德瓦特希望能够以最有效率的方式度过这几个小时。他打开 ProFitOro 应用，点击“开始”，然后开始工作。在完成文书工作后，他点击“停止”，在 ProFitOro 中检查自己的统计数据，并感到高兴。尽管他的工作时间只有两个小时，但他能够完成他计划完成的一切。

因此，我们可以提出一个正式的用户故事，如下所示：

作为一个经过验证的用户，我想要在 ProFitOro 上查看我的统计页面，以便了解我的工作日的完整性。

让我们继续介绍我们的健身教练史蒂夫·威尔逊。

史蒂夫·威尔逊

史蒂夫是一名健身教练。他对人体、营养知识以及如何正确进行锻炼了如指掌。他有很多朋友——都是使用 ProFitOro 应用的程序员。他在工作结束后回到家，登录并打开 ProFitOro 应用，点击“锻炼”部分，并添加了新的背部锻炼。

因此，一个新的正式用户故事可以是这样的：

作为一名健身教练，我希望能够轻松添加新的锻炼，以丰富 ProFitOro 应用的锻炼内容。

让我们继续介绍我们的学生安娜·库兹涅佐娃。

安娜·库兹涅佐娃

安娜是一名学生。目前，她正在经历考试期。她每天都需要为考试学习。在夏天，当所有朋友都出去玩时，要专心看书并不容易。有人告诉她 ProFitOro 应用程序可以帮助她集中注意力，所以她开始在没有注册的情况下使用它。过了一会儿，她意识到这实际上有助于她集中注意力。使用了一段时间后，她想要检查自己工作了多少时间，做了多少练习。然而，这些信息对非注册用户不可用。因此，她点击应用程序首页的**注册**按钮，用她的电子邮件注册，现在她可以访问她的统计数据了。

因此，又出现了另一个用户故事：

*作为非注册用户，我希望能够注册自己，以便能够登录应用程序并访问我的统计数据*。

# 检索名词和动词

从用户故事中检索名词和动词是一项非常有趣的任务，它可以帮助你意识到你的应用程序由哪些部分组成。对于那些喜欢**统一建模语言**（**UML**）的人来说，当你从用户故事中检索名词和动词后，你几乎已经完成了类和实体关系图！不要低估要检索的名词和动词的数量。把它们都写下来——真的！之后可以删除那些没有意义的词。所以，让我们开始吧。

## 名词

我能从我的用户故事中检索到的名词如下：

+   工作日

+   会议

+   电话

+   面试

+   小时

+   天

+   周

+   应用程序

+   统计

+   工作时间

+   计划

+   健身

+   教练

+   人体

+   营养

+   锻炼

+   部分

+   练习

+   电子邮件

+   数据

+   页面

+   注册

## 动词

我能从用户故事中检索到的动词如下：

+   包括

+   忙碌

+   打开

+   花时间

+   开始

+   暂停

+   停止

+   检查

+   完成

+   计划

+   添加

+   创建

+   注册

+   认证

+   登录

+   集中

我们有**注册**、**登录**和**认证**等动词，以及**电子邮件**和**注册**等名词，这意味着该应用程序可能会有注册和非注册两种使用方式。这意味着第一页可能会包含*登录*和*注册*区域，并且以某种方式，它还应该包含一个链接到可以在任何身份验证之前使用的应用程序。

然后，我们有动词如**开始**，**暂停**和**停止**。这些是适用于我们的番茄钟的主要动作。我们可以启动应用程序，我们可以暂停它，当然，我们可以在工作日的任何时候停止它。顺便说一句，**工作日**是我们检索到的名词之一。这意味着我们的应用程序的主页面将包含倒计时计时器，可以启动、暂停和停止。

我们有很多与健身相关的名词——**健身**本身，**人体**，**锻炼**，**训练**等等。这实际上是我们试图通过这个应用程序实现的目标——在番茄休息时训练我们的*身体*。因此，在工作休息时进行锻炼。注意还有动词如**检查**和**完成**。因此，锻炼可以被*完成*，并且某事可以被*检查*，表明用户已经*完成*了锻炼。这就是为什么，这个番茄间隔表示应该包含一个*复选框*。它还应该包含一个链接，指向下一个锻炼，以防你在当前锻炼上花费的时间较少。它还可能有一个跳过按钮，以防你在这个间隔期间完全不喜欢这个锻炼。

查看名词**统计**。这并不意味着我们必须讨论平均数、抽样、人口和其他一些年前在学校学到的东西。在我们的语境中，名词**统计**意味着用户应该能够访问他们在*一天*、*一周*或*一个月*内进行的锻炼的*统计数据*（注意名词列表中实际上有**天**和**周**这两个名词）。因此，将会有另一个屏幕显示用户的*统计数据*。

**计划**和**工作时间**。一些事情可以被计划并可能被配置。这是有道理的——一些用户可能觉得对于他们来说，工作时间应该是 30 分钟而不是 25 分钟。有些人可能需要更短的工作间隔，比如 15 或 20 分钟。这些数值应该是*可配置*的。因此，我们又来到了另一个屏幕——*配置*。在这个屏幕上，用户将能够重设他们的密码并配置他们的番茄钟工作时间，以及短时和长时休息时间。

查看动词**创建**和**添加**与名词**锻炼**相结合。我们已经讨论过番茄钟休息期间出现的锻炼是应用程序用户协作工作的结果。因此，应该有一个*部分*（检查名词列表中是否也包含**部分**这个词），允许*可视化*现有的锻炼和*创建*新的锻炼。

因此，根据先前的分析，我们将涉及 ProFitOro 应用程序的六个重要领域：

+   用户可以注册或登录的第一页。此页面还允许用户在未经身份验证的情况下开始使用应用程序。

+   番茄钟计时器所在的主页面。

+   主页面上显示番茄钟休息时间并显示在此休息期间要进行的锻炼的计时器。

+   可以更改用户设置，如用户名和个人资料图片，并配置番茄钟计时器的区域。

+   可以观察每天、每周或每月进行的锻炼的统计数据的区域。

+   显示所有现有锻炼并允许用户添加新锻炼的部分。

现在我们已经有了如何概述我们的应用程序的想法，我们可以开始考虑创建一些模型，以便更好地了解它，并尽早预见可能的问题。

# 模型

现在我们已经有了所有的名词和动词，我们可以开始在应用程序的所有部分之间建立联系。我们实际上可以开始准备一些模型。坐下来和某人讨论，解释你的想法，并收集反馈。提出问题。回答问题。使用白板，使用便条。使用纸张：绘制，丢弃，然后重新绘制。

我有一个名叫 Safura 的好朋友。她是一名在柏林学习计算机科学的在职学生，我们在同一个团队一起工作。她对 UI/UX 话题很感兴趣。实际上，她将在**人机交互**（**HCI**）领域撰写她的硕士论文。所以，我们坐在一起，我向她解释了 ProFitOro 的想法。你无法想象她提出的问题数量。然后，我们开始绘制。然后重新绘制。“如果……？”再次重绘。

这是纸上的第一批模型的样子：

![模型](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00054.jpeg)

ProFitOro 应用程序的纸上的第一批模型

在所有头脑风暴、绘图和重绘之后，Safura 为我准备了一些不错的模型。她使用*WireframeSketcher*进行此操作（[`wireframesketcher.com/`](http://wireframesketcher.com/)）。

## 第一页-登录和注册

用户看到的第一页是允许他们登录、注册或开始使用 ProFitOro 而无需注册的页面。页面如下所示：

![第一页-登录和注册](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00055.jpeg)

ProFitOro 应用程序的登录页面

措辞、颜色和图形尚未最终确定。模型的最重要部分是元素的定位。您仍将与设计师合作，并且仍然必须使用您喜爱的编程语言（对我们来说是 JavaScript/HTML/CSS）来实现这一点。模型有助于您记住应用程序的重要细节。

## 显示番茄钟的主页面

应用程序的下一个模型显示了番茄钟启动时的情况：

![显示番茄钟的主页面](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00056.jpeg)

应用程序的主屏幕——工作计时器已启动

正如您所看到的，我们的目标是拥有简单清晰的界面。标题区域有四个链接。它们如下：

+   **链接到设置页面**：它将打开用户的个人设置。用户可以更改个人数据，如密码、个人资料照片和番茄钟设置。

+   **链接到统计页面**：它将打开包含用户统计数据的弹出窗口。

+   **链接到锻炼**：这将打开包含所有可用锻炼的页面。该页面还将提供添加新锻炼的可能性。

+   **注销链接**

这些链接仅对已注册和经过身份验证的用户启用。对于匿名用户，这些链接将被禁用。

## 休息时锻炼

当工作的番茄钟结束时，将开始为期五分钟的小休息。在这段休息时间内，用户可以选择进行简单的小型锻炼：

![休息时锻炼](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00057.jpeg)

在短暂的休息时间内，用户有可能进行小型锻炼

正如您所看到的，锻炼区域提供以下内容：

+   首先，您可以完成锻炼并单击**完成**。此操作将将您的锻炼存储到您的统计数据中。

+   如果出于某种原因，您不想做建议的锻炼，但仍想做些事情，那么您可以单击**下一个**。这将为您提供一个新的随机选择的锻炼。

+   如果出于某种原因，您感到疲倦，根本不想锻炼，那么您可以点击**给我看小猫！**按钮，它将呈现一个区域，其中有随机的小猫，您可以盯着它们直到休息时间结束。

## 设置

如果用户想要更改他们的个人设置或番茄工作法的时间间隔，用户必须前往**设置**区域。这个区域看起来像这样：

![设置](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00058.jpeg)

ProFitOro 的设置区域

正如您所看到的，**设置**区域允许我们更改用户的个人数据并配置番茄工作法的时间。

## 统计

如果用户想要查看他们的统计数据并点击**统计**菜单按钮，将打开一个弹出窗口，其中显示了用户每天、每周和每月完成的锻炼的图表：

![统计](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00059.jpeg)

统计数据弹出窗口

## 锻炼

最后，如果您觉得您可能有一个在应用程序中不存在的锻炼想法，您可以随时打开**锻炼**部分并添加新的锻炼：

![锻炼](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00060.jpeg)

锻炼部分

正如您所看到的，在**锻炼**部分，用户可以查看整个锻炼列表，搜索它们，并编制自己的锻炼列表。默认情况下，应用程序中列出的所有锻炼将形成您的日常锻炼计划。然而，在这个区域，可以切换它们的选择。配置将为每个用户存储。

还可以创建新的锻炼。添加新的锻炼包括提供标题、描述和图片。

这些模型并不决定应用程序的最终外观。它们只是帮助我们定义首要任务和如何放置元素。在过程中，最终的位置和外观可能会发生很大变化。尽管如此，我们有严格的指导方针，这是项目管理和开发这个阶段最重要的成果。

## 标志

您可能已经注意到所有屏幕都包含一个漂亮的标志。这个标志是由我的一个非常好的朋友、一位名叫 Carina 的优秀平面设计师设计的。我已经在*学习 Vue.js 2*书中提到过这个标志，但我很乐意再次提到它。就在这里：

![标志](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00061.jpeg)

ProFitOro 的标志是由我的朋友 Carina 设计的

是不是很好？它是否反映了我们的应用程序将允许我们做的事情——结合番茄工作法和小锻炼？我们甚至定义了 ProFitOro 的座右铭：

> 工作期间休息。休息期间锻炼。

# 总结

在本章中，我们应用了设计应用程序用户界面的基本原则。我们进行了头脑风暴，定义了我们的角色并编写了用户故事，从这些故事中提取了名词和动词，并最终为我们的应用程序设计了一些不错的模型。

在下一章中，我们将开始实现我们的 ProFitOro。我们将使用 Vue.js 来搭建应用程序并将其拆分为重要的组件。因此，在下一章中我们将做以下事情：

+   使用`webpack`模板使用 vue-cli 搭建 ProFitOro 应用程序

+   将应用程序拆分为组件并为应用程序创建所有必要的组件

+   使用 Vue.js 和 Bootstrap 实现一个基本的番茄钟定时器


# 第四章：让它成为番茄钟！

上一章以一组*ProFitOro*应用程序的模拟图结束。我们之前已经定义了应用程序应该做什么；我们还确定了一个平均用户配置文件，并且准备好实现它。在这一章中，我们将最终开始编码。因此，在这一章中，我们将做以下事情：

+   使用`webpack`模板使用 vue-cli 搭建*ProFitOro*

+   定义所有需要的应用程序组件

+   为所有组件创建占位符

+   实现一个组件，负责使用 Vue.js 和 Bootstrap 渲染番茄钟计时器

+   重新审视三角函数的基础知识（你没想到会有这个吧？）

# 创建应用程序的骨架

在一切之前，让我们确保我们至少在节点版本上是一致的。我使用的 Node.js 版本是*6.11.1*。

让我们从为我们的应用程序创建一个骨架开始。我们将使用`webpack`模板的 vue-cli。如果你不记得**vue-cli**是什么以及它来自哪里，请查看官方 Vue 文档，网址为[`github.com/vuejs/vue-cli`](https://github.com/vuejs/vue-cli)。如果由于某种原因你还没有安装它，请继续安装：

```js
**npm install -g vue-cli**

```

现在，让我们引导我们的应用程序。我相信你记得，为了使用`vue-cli`初始化应用程序，你必须运行`vue init`命令，后面跟着要使用的模板名称和项目本身的名称。我们将使用`webpack`模板，我们的应用程序名称是`profitoro`。所以，让我们初始化它：

```js
**vue init webpack profitoro**

```

在初始化过程中，会有一些问题需要回答。只需一直按*Enter*键回答默认的`Yes`即可；因为对于这个应用程序，我们需要一切：代码检查、vue-router、单元测试、端到端测试，全部都需要。这将会很庞大！

你的控制台输出应该几乎和我的一样：

![创建应用程序的骨架](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00062.jpeg)

应用程序初始化时的控制台输出

现在，在新创建的`profitoro`目录中运行`npm install`：

```js
**cd profitoro**
**npm install**

```

让我们安装`sass`加载器，因为我们将使用`sass`预处理器来为我们的应用程序添加样式：

```js
**npm install sass-loader node-sass --save-dev**

```

最后，我们准备运行它：

```js
**npm run dev**

```

您的新 Vue 应用程序已准备就绪。为了让我们的 ProFitOro 有一个干净的工作环境，删除与默认安装过程一起安装的`Hello`组件相关的一切。作为替代方案，只需打开第四章 *让它番茄钟！*的代码文件，并从`chapter4/1/profitoro`文件夹中获取样板代码。

# 定义 ProFitOro 组件

我们的应用程序由两个主要屏幕组成。

其中一个屏幕是所谓的*登陆页面*；该页面由以下部分组成：

+   一个标志

+   一个标语

+   一个认证部分

+   一个可供未注册用户使用的应用程序链接

从图表上看，这是我们组件在屏幕上的位置：

![定义 ProFitOro 组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00063.jpeg)

包含标志、标语、认证部分和应用程序链接的登陆页面

第二个屏幕是主应用程序屏幕。该屏幕包含三个部分：

+   一个页眉

+   一个页脚

+   内容

内容部分包含番茄钟计时器。如果用户已经认证，它将包含设置、锻炼和统计信息：

![定义 ProFitOro 组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00064.jpeg)

包含页眉、页脚和内容的主应用程序屏幕

让我们创建一个名为`components`的文件夹，以及名为`main`、`landing`和`common`的子文件夹，用于相应的子组件。

登陆页面和主页面的组件将存放在`components`文件夹中；其余的 11 个组件将分布在相应的子文件夹中。

对于每个定义的组件文件，添加`template`、`script`和`style`部分。在`style`标签中添加`lang="sass"`属性，因为正如我之前提到的，我们将使用`sass`预处理器来为我们的组件添加样式。因此，例如，`HeaderComponent.vue`将如下所示：

```js
//HeaderComponent.vue
<template>
  <div>**Header**</div>
</template>
<script>
  export default {

  }
</script>
<style scoped **lang="sass"**>

</style>
```

因此，我们有 13 个准备好填充必要数据的组件占位符。这些组件将被使用和重复使用。这是因为 Vue 组件是*可重用组件*，这就是它们如此强大的原因。在开发过程中，我们将不可避免地添加更多组件和子组件，但这是我们的基础：

![定义 ProFitOro 组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00065.jpeg)

ProFitOro 的 13 个基础组件

检查我们在`chapter4/2/profitoro`文件夹中的基础组件。

让我们也通过填充所需的子组件来准备我们的`LandingPage`和`MainContent`组件。在此之前，为每个子文件夹添加一个`index.js`文件，并在其中导出相应子文件夹的内容。这将使之后的导入更容易。因此，从`common`文件夹开始，并添加以下内容的`index.js`文件：

```js
//common/index.js
export {default as Logo} from './Logo'
```

对`sections`，`main`和`landing`文件夹重复相同的操作。

现在我们可以组合我们的登陆页面和主要内容组件。让我们从`LandingPage.vue`开始。这个组件包括一个标志，一个认证部分，一个指向应用程序的链接和一个标语。导入所有这些组件，将它们导出到`components`对象中，并在`template`中使用它们！我们在`index.js`文件中导出这些组件的事实使我们可以像下面这样导入它们：

```js
//LandingPage.vue
import {Authentication, GoToAppLink, Tagline} from './landing'
import {Logo} from './common'
```

现在我们可以在`LandingPage`组件的`components`对象中使用这些导入的组件。顺便说一句，你有没有见过同一个短语中有这么多*组件*这个词？"组件，组件，组件"，导出的对象看起来如下：

```js
//LandingPage.vue
export default {
  components: {
    Logo,
    Authentication,
    GoToAppLink,
    Tagline
  }
}
```

在`components`对象中导出后，所有这些组件都可以在模板中使用。请注意，所有**驼峰命名**的内容在模板中都会变成**短横线命名**。因此，我们的`GoToAppLink`看起来会像`go-to-app-link`。因此，我们模板中的组件将如下所示：

```js
<logo></logo>
<tagline></tagline>
<authentication></authentication>
<go-to-app-link></go-to-app-link>
```

因此，我们整个`LandingPage`组件现在将有以下代码：

```js
//LandingPage.vue
<template>
  <div>
    **<logo></logo>**
 **<tagline></tagline>**
 **<authentication></authentication>**
 **<go-to-app-link></go-to-app-link>**
  </div>
</template>
<script>
  import {**Authentication, GoToAppLink, Tagline**} from './landing'
  import {**Logo**} from **'./common'**
  export default {
    components: {
      **Logo,**
 **Authentication,**
 **GoToAppLink,**
 **Tagline**
    }
  }
</script>
<style scoped lang="sass">

</style>
```

让我们告诉`App.vue`来渲染这个组件：

```js
//App.vue
<template>
  <div id="app">
    <h1>Welcome to Profitoro</h1>
    **<landing-page></landing-page>**
  </div>
</template>

<script>
  **import LandingPage from './components/LandingPage'**
  export default {
    name: 'app',
    components: {
      LandingPage
    }
  }
</script>
```

检查页面。你能看到你的组件吗？我相信你可以：

![定义 ProFitOro 组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00066.jpeg)

LandingPage 组件

现在，我们*只需*实现相应的组件，我们的登陆页面就准备好了！

## 练习

对于`MainContent`组件也要做同样的操作——导入和导出所有必要的子组件，并将它们添加到模板中。之后，在`App.vue`中调用`MainContent`组件，就像我们刚刚在`LandingPage`组件中所做的那样。如果有疑问，请检查`chapter4/3/profitoro`文件夹中的代码。

# 实现番茄钟计时器

我们应用程序中最重要的组件之一，毫无疑问，就是番茄钟计时器。它执行应用程序的主要功能。因此，首先实现它可能是一个好主意。

我在想一种圆形计时器。类似这样的：

![实现番茄钟计时器](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00067.jpeg)

圆形计时器将被实现为番茄钟

随着时间的推移，突出显示的扇形将逆时针移动，时间也将倒计时。为了实现这种结构，我考虑了三个组件：

+   *SvgCircleSector*：此组件将只接收一个角度作为属性，并着色 SVG 圆的相应扇形。

+   *CountDownTimer*：此组件将接收要倒计时的秒数，实现计时器并在每次计时器更新时计算要传递给`SvgCircularComponent`的角度。

+   *PomodoroTimer*：我们已经引导了这个组件。此组件将负责使用初始时间调用`CountDownTimer`组件，并根据当前工作的番茄钟或休息间隔更新到相应的秒数。

## SVG 和三角函数

让我们首先定义我们的`SvgCircleSector`组件。这个组件将接收`angle`和`text`作为属性，并绘制一个具有给定角度突出显示扇形的 SVG 圆。在`components/main/sections`文件夹内创建一个名为`timer`的文件夹，然后在其中创建一个`SvgCircleSector.vue`文件。定义`template`、`script`和`style`所需的部分。您还可以导出`props`，其中包括此组件将从其父级接收的`angle`和`text`属性：

```js
//SvgCircleSector.vue
<template>
  <div>
  </div>
</template>
<script>
  export default {
    **props: ['angle', 'text']**
  }
</script>
<style scoped lang="scss">
</style>
```

那么，我们如何使用 SVG 绘制圆并突出显示其扇形？首先，让我们绘制两个圆：一个在另一个内部。让我们将较大的圆半径设为`100px`，较小的圆半径设为`90px`。基本上，我们必须提供中心、*x*和*y*坐标、半径（`r`）和`fill`属性。查看 SVG 中关于圆的文档，网址为[`developer.mozilla.org/en-US/docs/Web/SVG/Element/circle`](https://developer.mozilla.org/en-US/docs/Web/SVG/Element/circle)。我们最终会得到类似于这样的东西：

```js
<svg width="200" height="200" >
  <circle r="100" cx="100" cy="100" fill="gray"></circle>
  <circle r="90" cx="100" cy="100" fill="lightgray"></circle>
</svg>
```

因此，我们得到了两个圆，一个在另一个内部。

![SVG 和三角函数](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00068.jpeg)

使用 SVG 圆元素绘制的两个圆

现在，为了绘制圆的突出显示扇形，我们将使用*path* SVG 元素（[`developer.mozilla.org/en-US/docs/Web/SVG/Element/path`](https://developer.mozilla.org/en-US/docs/Web/SVG/Element/path)）。

使用 SVG 路径元素，您可以绘制任何您想要的东西。它的主要属性称为`d`，基本上是一种使用 SVG 特定领域语言编程路径的方式。例如，这是如何在我们的圆内绘制一个三角形：

```js
<path d="M100,100 V0 L0,100 H0 z"></path>
```

这些代码代表什么？ `M`代表*移动*，`L`代表*线*，`V`代表*垂直线*，`H`代表*水平线*，`z`代表*在此停止路径*。因此，我们告诉我们的路径首先移动到`100`，`100`（圆心），然后画一条垂直线直到达到*y*轴的`0`点，然后画一条线到`0`，`100` *x*，*y*坐标，然后画一条水平线直到达到`100` *x*坐标，然后停止。我们的二维坐标区由*x*和*y*轴组成，其中*x*从左到右从`0`开始，直到`200`，*y*从上到下从`0`开始，直到`200`。

这是我们小圆坐标系的中心和极端点的(*x*, *y*)坐标的样子：

![SVG 和三角函数](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00069.jpeg)

标记的点代表 SVG 圆的(x,y)坐标，圆心在(100,100)

因此，如果我们从(`100`,`100`)开始，画一条垂直线到(`100`,`0`)，然后画一条线到(`0`, `100`)，然后画一条水平线直到(`100`,`100`)，我们最终得到一个在我们的圆的左上象限内绘制的直角三角形：

![SVG 和三角函数](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00070.jpeg)

路径在圆内绘制一个三角形

这只是对路径 SVG 元素的一个小介绍，以及它可以实现的内容。然而，我们仍然需要绘制一个圆形扇区，而不仅仅是一个三角形。为了使用路径绘制扇区，我们可以在`d`属性内部使用`A`命令。 `A`代表*弧*。这可能是路径中最复杂的命令。它接收以下信息：*rx, ry, x-axis-rotation, large-arc-flag, sweep-flag, x, y*。

在我们的情况下，前四个属性始终可以是`100`，`100`，`0`，`0`。如果您想了解原因，请查看 w3c 关于弧路径属性的文档[`www.w3.org/TR/SVG/paths.html#PathDataEllipticalArcCommands`](https://www.w3.org/TR/SVG/paths.html#PathDataEllipticalArcCommands)。 

对我们来说，最重要的属性是最后三个。*sweep-flag*表示*弧*的方向；它可以是`0`或`1`，分别表示顺时针和逆时针方向。在我们的情况下，它将始终为*0*，因为这是我们希望弧线绘制的方式（逆时针）。至于最后的*x*和*y*值，这些值决定了弧线的停止位置。因此，例如，如果我们想在*90*度处绘制左上方的扇形，我们将在(`0`, `100`)坐标处停止弧线—*x*为`0`，*y*为`100`—因此我们的`d`属性将如下所示：

```js
d="M100,100 L100,0 **A**100,100 0 0,0 **0,100** z"
```

包含两个圆和扇形的整个 SVG 元素将如下所示：

```js
<svg width="200" height="200" >
  <circle r="100" cx="100" cy="100" fill="gray"></circle>
  <circle r="90" cx="100" cy="100" fill="lightgray"></circle>
  <path id="sector" fill="darkgray" opacity="0.6" **d="M100,100 L100,0 A100,100 0 0,0 0, 100 z"**></path>
</svg>
```

这段代码产生了以下结果：

![SVG 和三角函数](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00071.jpeg)

用 SVG 元素的路径绘制的 90 度扇形

我们实际上必须将这个`d`属性定义为一个动态属性，其计算值将取决于。为了表示这一点，我们必须使用`v-bind`，后面跟着一个分号和属性：`v-bind:d`，或者简单地写为`:d`。让我们给相应的属性路径命名，并将其添加到我们组件的导出对象`computed`中：

```js
//SvgCircleSector.vue
<template>
  <div>
    <svg class="timer" width="200" height="200" >
      <...>
      <path class="segment" **:d="path"**></path>
    </svg>
  </div>
</template>
<script>
  function **calcPath** (angle) {
    let d
    **d = "M100,100 L100,0 A100,100 0 0,0 0, 100 z"**
    return d
  }
  export default {
    props: ['angle', 'text'],
    computed: {
      path () {
        **return calcPath(this.angle)**
      }
    }
  }
</script>
```

我引入了一个名为`calcPath`的函数，它将确定我们的路径字符串。目前，它返回的路径将突出显示*90*度的区域。

我们几乎完成了。我们实际上可以绘制一个段，但缺少的是能够为任何角度绘制一个段的能力。我们的`SvgCircleSector`组件将接收一个角度作为属性。这个角度不总是等于*90*度。我们应该想出一个公式，根据`angle`来计算结束的*x*和*y*坐标。如果你对重新学习基本的三角函数不感兴趣，可以跳过这部分，继续阅读本节的结尾。

这是我计算小于 180 度角的*x*，*y*坐标的方法：

![SVG 和三角函数](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00072.jpeg)

要计算角度α的(x,y)坐标，我们需要计算直角三角形的 a 和 b 边。

从图中我们可以看到：

```js
x = 100 – b
y = 100 – a
```

因此，我们只需要计算`a`和`b`。这是一项简单的任务。我们可以通过知道角度和斜边来计算直角三角形的两条腿。斜边`c`等于圆的半径（在我们的例子中为`100`）。与角度相邻的腿`a`等于`c * cosα`，而与角度相对的腿`b`等于`c * sin` `α`。因此：

```js
x = 100 – 100 * sinα
y = 100 – 100 * cosα
```

对于大于 180 度的角度，我们有以下方案：

![SVG 和三角学](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00073.jpeg)

对于大于 180°的角度，我们还必须计算右三角形的两边

我可以告诉你一个秘密吗？我真的很不擅长画这种图。我尝试过从纸上的草图到使用 Gimp 进行绘画。一切看起来都很丑。幸运的是，我有我的哥哥*伊利亚*，他用 Sketch 在五分钟内创建了这些图形。非常感谢你，*伊鲁什卡*！

回到我们的例子。在这种情况下，右三角形的角度等于`270° -` `α`。我们的`x`等于`100 + b`，`y`等于`100 + a`。以下是简单的计算：

```js
a = c * sin (270 - α)
a = c * sin (180 + (90 - α))
a = -c * sin (90 - α)
a = -c * cosα
b = c * cos (270 - α)
b = c * cos (180 + (90 - α))
b = -c * cos (90 - α)
b = -c * sinα
```

因此：

```js
x = 100 + (-100 * sinα) = 100 – 100*sinα
y = 100 + (-100 * cosα) = 100 – 100*cosα
```

这与小于*180*度的角度完全相同！

这是用于计算*x*，*y*坐标的 JavaScript 代码：

```js
function calcEndPoint (angle) {
  let x, y

  **x = 100 - 100 * Math.sin(Math.PI * angle / 180)**
 **y = 100 - 100 * Math.cos(Math.PI * angle / 180)**

  return {
    x, y
  }
}
```

现在，我们终于可以定义一个函数，根据角度确定路径元素的`d`字符串属性。这个函数将调用`calcEndPoint`函数，并返回一个包含最终`d`属性的`string`：

```js
function calcPath (angle) {
  let d
  let {x, y} = calcEndPoint(angle)
  if (angle <= 180) {
    d = `M100,100 L100, 0 A100,100 0 0,0 ${x}, ${y} z`
  } else {
    d = `M100,100 L100, 0 A100,100 0 0,0 100, 200 A100,100 0 0,0 ${x}, ${y} z`
  }
  return d
}
```

为了完成我们的组件，让我们引入一个文本 SVG 元素，它将只渲染传递给组件的文本属性。也应该可以绘制一个没有任何文本的圆；因此，让我们使用`v-if`指令来实现这一点：

```js
//SvgCircleSector.vue
<template>
  <div>
    <svg class="timer" width="200" height="200" >
      <...>
      <text **v-if="text != ''"** class="text" x="100" y="100">
        **{{text}}**
      </text>
    </svg>
  </div>
</template>
```

让我们还提取大圆和小圆的样式，以及路径和文本的样式到`style`部分。让我们定义有意义的类，这样我们的模板将如下所示：

```js
//SvgCircleSector.vue
<template>
  <div>
    <svg class="timer" width="200" height="200" >
      <circle class="**bigCircle**" r="100" cx="100" cy="100"></circle>
      <circle class="**smallCircle**" r="90" cx="100" cy="100"></circle>
      <path class="**segment**" :d="path"></path>
      <text v-if="text != ''" class="**text**" x="100" y="100">
        {{text}}
      </text>
    </svg>
  </div>
</template>
```

在`style`标签内，让我们定义颜色变量，并将它们用于我们的圆。将颜色提取到变量中将有助于我们在将来轻松地更改它们，如果我们决定更改应用程序的颜色方案。因此，我们的 SVG 组件的样式将如下所示：

```js
//SvgCircleSector.vue
<style scoped lang="scss">
  **$big-circle-color: gray;**
 **$small-circle-color: lightgray;**
 **$segment-color: darkgray;**
 **$text-color: black;**

  .bigCircle {
    fill: $big-circle-color;
  }
  .smallCircle {
    fill: $small-circle-color;
  }
  .segment {
    fill: $segment-color;opacity: 0.6;
  }
  .text {
    font-size: 1em;
    stroke-width: 0;
    opacity: .9;
    fill: $text-color;
  }
</style>
```

### 练习

到目前为止，我们一直在使用绝对大小的圆；它的半径始终为`100`像素。使用`viewBox`和`preserveAspectRatio`属性应用于`svg`元素，使我们的圆响应式。试着玩一下；在`PomodoroTimer`组件中调用这个组件，使用不同的角度属性来看看它是如何工作的。我能想出这样疯狂的页面：

![练习](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00074.jpeg)

由许多 SVG 圆组成的疯狂页面，其扇形由给定角度定义

检查`chapter4/4/profitoro`文件夹中的代码。特别注意`components/sections/timer`文件夹中的`SvgCircleSector.vue`组件，以及调用圆形组件多次并使用不同的角度属性的`PomodoroTimer.vue`组件。

## 实现倒计时计时器组件

现在我们有一个完全功能的组件，它可以根据给定的角度渲染一个带有高亮区域的圆形，我们将实现`CountDownTimer`组件。这个组件将接收一个倒计时的秒数作为属性。它将包含控件元素：一组按钮，允许你*开始*、*暂停*和*停止*计时器。一旦计时器启动，秒数将被倒计时，并相应地重新计算角度。这个重新计算的角度被传递给`SvgCircleSector`组件，以及计算出的文本。文本将包含计时器结束时剩余的分钟和秒数。

首先，在`components/main/sections/timer`文件夹中创建一个`CountDownTimer.vue`文件。让我们从这个组件中调用`SvgCircleSector`组件，并为`angle`和`text`属性设置一些任意值：

```js
**//CountDownTimer.vue**
<template>
  <div class="container">
    <div>
      <**svg-circle-sector** **:angle="30"** **:text="'Hello'"**></**svg-circle-sector**>
    </div>
  </div>
</template>
<script>
  **import SvgCircleSector from './SvgCircleSector'**
  export default {
    components: {
      **SvgCircleSector**
    }
  }
</script>
<style scoped lang="scss">

</style>
```

打开页面。有点太大了。甚至不适合我的屏幕：

![实现倒计时计时器组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00075.jpeg)

我们的组件不适合我的屏幕

然而，如果我在手机上打开它，它会渲染得很好，实际上看起来很好：

![实现倒计时计时器组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00076.jpeg)

我们的组件在移动屏幕上实际上非常合适

这是因为我们的圆是响应式的。如果你尝试调整浏览器的大小，你会发现圆形会相应地调整大小。它的宽度始终是浏览器的*100%*。当页面的高度大于宽度时（这是移动浏览器的情况），它看起来很好，但当宽度大于高度时（如在桌面屏幕的情况下），它看起来非常大和丑陋。所以，我们的圆是响应式的，但并不是真正适应性的。但我们正在使用 Bootstrap！Bootstrap 在响应性和适应性方面是一个很好的朋友。

## 使用 Bootstrap 实现倒计时计时器的响应性和适应性

为了实现对任何设备的适应性，我们将使用 Bootstrap 网格系统来构建我们的布局，网址为[`v4-alpha.getbootstrap.com/layout/grid/`](https://v4-alpha.getbootstrap.com/layout/grid/)。

### 注意

请注意，此 URL 是用于 alpha 版本的，下一个版本将在官方网站上提供。

此系统基于十二列行布局。`row`和`col`类包括不同的层级，每个媒体查询一个。因此，相同的元素可以根据设备大小具有不同的相对大小。这些类的名称是不言自明的。包装行类名为`row`。然后，每列可能有一个名为`col`的类。例如，这是一个具有相等大小的四列的简单行：

```js
<div class="**row**">
  <div class="**col**">Column 1</div>
  <div class="**col**">Column 2</div>
  <div class="**col**">Column 3</div>
  <div class="**col**">Column 4</div>
</div>
```

此代码将产生以下结果：

![使用 Bootstrap 实现倒计时器的响应性和适应性](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00077.jpeg)

具有四个相等大小列的 Bootstrap 行

类`col`可以与您要为列指定的大小相结合：

```js
<div class="**col-***">Column 1</div>
```

在这里，`*`可以是从`1`到`12`的任何内容，因为每行最多可以包含十二列。以下是具有四个不同大小列的行的示例：

```js
<div class="row">
  <div class="**col-6**">Column 1</div>
  <div class="**col-3**">Column 2</div>
  <div class="**col-2**">Column 3</div>
  <div class="**col-1**">Column 4</div>
</div>
```

因此，第一列将占据一半的行，第二列将占据四分之一的行，第三列将占据六分之一的行，最后一列将占据十二分之一的行。这是它的样子：

![使用 Bootstrap 实现倒计时器的响应性和适应性](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00078.jpeg)

具有不同大小列的 Bootstrap 行

不要在意黑色边框；我添加它们是为了使列宽更加明显。Bootstrap 将在没有任何边框的情况下绘制您的布局，除非您告诉它包括它们。

Bootstrap 还提供了一种偏移列的技术，可以在[`v4-alpha.getbootstrap.com/layout/grid/#offsetting-columns`](https://v4-alpha.getbootstrap.com/layout/grid/#offsetting-columns)上找到。

### 注意

请注意，此 URL 是用于 alpha 版本的，下一个版本将在官方网站上提供。

例如，我们如何制作两列，其中一列的大小为`6`，另一列的大小为`2`，偏移量为`4`：

```js
<div class="**row**">
  <div class="**col-6**">Column 1</div>
  <div class="**col-2 offset-4**">Column 2</div>
</div>
```

这是它的样子：

![使用 Bootstrap 实现倒计时器的响应性和适应性](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00079.jpeg)

具有两列的行，其中一列显示偏移量为 4。

您甚至可以通过使用`push-*`和`pull-*`类来玩转列并更改它们的顺序。有关更多信息，请访问[`v4-alpha.getbootstrap.com/layout/grid/#push-and-pull`](https://v4-alpha.getbootstrap.com/layout/grid/#push-and-pull)。

### 注意

请注意，此 URL 是用于 alpha 版本的，下一个版本将在官方网站上提供

这些类几乎扮演了`offset-*`类的相同角色；它们为您的列提供了更多的灵活性。例如，如果我们想要呈现大小为`3`的列和大小为`9`的列并更改它们的顺序，我们将需要将大小为`3`的列推送到`9`的位置，并将大小为`9`的列拉到`3`的位置：

```js
<div class="row">
  <div class="**col-3 push-9**">Column 1</div>
  <div class="**col-9 pull-3**">Column 2</div>
</div>
```

此代码将产生以下布局：

![使用 Bootstrap 实现倒计时计时器的响应和适应性](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00080.jpeg)

使用 push-*和 pull-*类更改列的顺序

尝试所有这些示例，并检查无论如何调整页面大小，布局的比例都将始终相同。这是 Bootstrap 布局的一个强大功能；您甚至不必费心使您的布局响应。我在本节的第一段中提到的不同设备怎么样？到目前为止，我们一直在探索称为`col-*`、`offset-*`、`push-*`和`pull-*`的类。Bootstrap 还为每种媒体查询提供了这组类。

Bootstrap 中有五种设备类型：

| **xs** | 超小设备 | 竖屏手机（<544px） |
| --- | --- | --- |
| **sm** | 小设备 | 横屏手机（≥544px - <768px） |
| **md** | 中等设备 | 平板电脑（≥768px - <992px） |
| **lg** | 大设备 | 桌面电脑（≥992px - <1200px） |
| **xl** | 超大设备 | 桌面电脑（≥1200px） |

为了指示在给定设备上的期望行为，您只需在类名和其大小之间传递设备指定。因此，例如，如果您希望大小分别为`8`和`4`的两列在移动设备上转换为两个堆叠的列，您可以执行以下操作：

```js
<div class="row">
  <div class="col-sm-12 col-md-8">Column 1</div>
  <div class="col-sm-12 col-md-4">Column 2</div>
</div>
```

如果您在浏览器中打开此代码并尝试调整页面大小，您会发现一旦大小小于`544`像素，列将堆叠：

![使用 Bootstrap 实现倒计时计时器的响应和适应性](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00081.jpeg)

两列布局在小屏幕上变成了堆叠的等大小列布局

那么我们应该怎么处理我们的计时器？我会说它可以在小设备上占据整个宽度（*100%*），在中等宽度设备上占据宽度的 2/3，在大设备上变为宽度的一半，在超大设备上为宽度的 1/3。因此，它将需要以下类：

+   **col-sm-12** 用于小设备

+   **col-md-8** 用于中等宽度设备

+   **col-lg-6** 用于大设备

+   **col-xl-4** 用于超大设备

我还希望我的圆圈出现在屏幕中央。为此，我将应用`justify-content-center`类到行中：

```js
<div class="row **justify-content-center**">
  <svg-circle-sector class="**col-sm-12 col-md-8 col-lg-6 col-xl-4**" :angle="30" :text="'Hello'"></svg-circle-sector>
</div>
```

打开页面并尝试调整大小，模拟不同的设备，测试纵向和横向视图。我们的圆圈会相应地调整大小。检查`chapter4/5/profitoro`文件夹中的代码；特别注意`components/CountDownTimer.vue`组件。

## 倒计时计时器组件- 让我们倒计时！

我们已经实现了倒计时计时器组件的响应性。让我们最终将其变成一个真正的倒计时计时器组件。让我们首先添加控件：开始、暂停和停止按钮。现在，我会让它们看起来像链接。为此，我将使用 Bootstrap 的`btn-link`类在[`v4-alpha.getbootstrap.com/components/buttons/`](https://v4-alpha.getbootstrap.com/components/buttons/)。

### 注意

请注意，此 URL 是用于 alpha 版本的，下一个版本将在官方网站上提供。

我还将使用 Vue 的`v-on`指令在每个按钮点击时绑定一个方法在[`vuejs.org/v2/api/#v-on`](https://vuejs.org/v2/api/#v-on)：

```js
<button **v-on:click="start">Start</button>**
```

或者，我们可以简单地使用：

```js
<button **@click="start"**>Start</button>
```

因此，按钮的代码将如下所示：

```js
<div class="controls">
  <div class="btn-group" role="group">
    <button **@click="start"** type="button" class="**btn btn-link**">Start</button>
    <button **@click="pause"** type="button" class="**btn btn-link**">Pause</button>
    <button **@click="stop"** type="button" class="**btn btn-link**">Stop</button>
  </div>
</div>
```

将`text-center`类添加到包装容器`div`中，以便按钮居中对齐。现在，有了控制按钮，我们的计时器看起来像这样：

![倒计时计时器组件- 让我们倒计时！](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00082.jpeg)

带控制按钮的倒计时计时器

当我们开始讨论这个组件时，我们说它将从其父组件接收以秒为单位的倒计时时间。让我们添加一个名为`time`的属性，并让我们从父组件传递这个属性：

```js
//CountDownTimer.vue
<script>
  <...>
  export default {
    **props: ['time']**
    <...>
  }
</script>
```

现在，让我们将这个属性作为计算的硬编码属性导出到`PomodorTimer`组件中，并将其绑定到`CountDownTimer`组件。让我们将其硬编码为`25`分钟，或`25 * 60`秒：

```js
//PomodoroTimer.vue
<template>
  <div>
    <count-down-timer **:time="time"**></count-down-timer>
  </div>
</template>
<script>
  import CountDownTimer from './timer/CountDownTimer'
  export default {
    **computed: {**
 **time () {**
 **return 25 * 60**
 **}**
 **}**,
    components: {
      CountDownTimer
    }
  }
</script>
```

好的，所以我们的倒计时组件接收以秒为单位的时间。它将如何更新`角度`和`文本`？由于我们无法更改父级的属性(`时间`)，我们需要引入属于该组件的值，然后我们将能够在组件内部更改它，并根据该值计算角度和文本值。让我们引入这个新值并称之为`时间戳`。将其放在倒计时组件的数据函数中：

```js
//CountDownTimer.vue
data () {
  return {
    **timestamp: this.time**
  }
},
```

现在让我们为`angle`添加一个计算值。我们如何根据时间戳（以秒为单位）计算角度？如果我们知道每秒的角度值，那么我们只需将该值乘以所需秒数即可：

```js
angle = DegreesPerSecond * this.timestamp
```

知道初始时间（以秒为单位），很容易计算每秒的度数。由于整个周长为*360 度*，我们只需将*360*除以*初始时间*即可：

```js
DegreesPerSecond = 360/this.time
```

最后但同样重要的是，由于我们的计时器是逆时针计时器，我们需要将逆角度传递给`SvgCircleSector`组件，因此我们的最终计算角度值将如下所示：

```js
  computed: {
    **angle** () {
      **return 360 - (360 / this.time * this.timestamp)**
    }
  }
```

通过角度的值替换模板中的硬编码角度绑定：

```js
<svg-circle-sector **:angle="angle"**></svg-circle-sector>
```

调整`timestamp`的值；尝试将其从`0 * 60`设置为`25 * 60`。您将看到高亮区域如何相应地更改：

![倒计时计时器组件-让我们倒计时！](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00083.jpeg)

圆圈的高亮区域随着给定的时间戳而相应地变化

我不确定你，但我已经厌倦了看到这个 Hello。让我们做点什么。计时器的文本应显示剩余时间直到倒计时结束的分钟数和秒数；它对应于计时器圆圈的未高亮区域。这是一个非常简单的计算。如果我们将时间戳除以`60`并获得除法的整数部分，我们将得到当前分钟数。如果我们获得这个除法的余数，我们将得到当前秒数。文本应该显示分钟和秒数除以冒号（`:`）。因此，让我们添加这三个计算值：

```js
//CountDownTimer.vue
computed: {
  angle () {
    return 360 - (360 / this.time * this.timestamp)
  },
  **minutes** () {
    return **Math.floor(this.timestamp / 60)**
  },
  **seconds** () {
    return **this.timestamp % 60**
  },
  **text** () {
    return **`${this.minutes}:${this.seconds}`**
  }
},
```

请注意，我们在计算文本时使用了`ES6`模板（[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Template_literals`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Template_literals)）。

最后，用文本值替换属性绑定中的硬编码字符串`Hello`：

```js
<svg-circle-sector :angle="angle" **:text="text"**></svg-circle-sector>
```

现在好多了吧？

![倒计时计时器组件-让我们倒计时！](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00084.jpeg)

计时器的文本根据剩余时间而变化

现在唯一缺少的是实际启动计时器并进行倒计时。我们已经在每个相应的按钮点击上调用了`start`、`pause`和`stop`方法。让我们创建这些方法：

```js
//CountDownTimer.vue
methods: {
  **start** () {
  },
  **pause** () {
  },
  **stop** () {
  }
},
```

这些方法内部应该发生什么？`start`方法应该设置一个间隔，每秒减少一秒的计时器。`pause`方法应该暂停这个间隔，`stop`方法应该清除这个间隔并重置时间戳。在组件的数据函数中引入一个名为`interval`的新变量，并添加所需的方法：

```js
//CountDownTimer.vue
data () {
  return {
    timestamp: this.time,
    **interval**: null
  }
},
<...>
methods: {
  **start** () {
    this.interval = **setInterval**(() => {
      **this.timestamp--**
      if (this.timestamp === 0) {
        this.timestamp = this.time
      }
    }, 1000)
  },
  **pause** () {
    **clearInterval**(this.interval)
  },
  **stop** () {
    **clearInterval**(this.interval)
    this.timestamp = this.time
  }
}
```

然后...我们完成了！打开页面，点击控制按钮，尝试不同的初始时间值，并检查它的工作情况！检查`chapter4/6/profitoro`文件夹中`CountDownTimer`组件的代码。

### 练习

我们的倒计时器看起来很不错，但仍然存在一些问题。首先，文本看起来不太好。当分钟或秒数少于`9`时，它会显示相应的文本，而不带有尾随的`0`，例如，*5 分钟 5 秒*显示为**5:5**。这看起来并不像时间。引入一个方法，让我们称之为`leftpad`，它将为这种情况添加一个额外的`0`。请尽量不要破坏互联网！（[`www.theregister.co.uk/2016/03/23/npm_left_pad_chaos/`](https://www.theregister.co.uk/2016/03/23/npm_left_pad_chaos/)）

我们的计时器的另一个问题是我们可以随时点击任何按钮。如果你频繁点击启动按钮，结果会出乎意料地难看。引入三个数据变量——`isStarted`，`isPaused`和`isStopped`——它们将根据每个方法进行切换。将`disabled`类绑定到控制按钮。这个类应该根据提到的变量的值来激活。所以，行为应该是以下的：

+   如果计时器已经启动并且没有暂停，启动按钮应该被禁用。

+   如果计时器没有启动，暂停和停止按钮应该被禁用。如果计时器已经暂停或停止，它们也应该被禁用。

要有条件地绑定类，使用`v-bind:className={expression}`，或者简单地使用`:className={expression}`表示法。例如：

```js
<button **:class="{disabled: isStarted}"**>Start</button>
```

要自己检查一下，请查看`chapter4/7/profitoro`目录，特别是`components/CountDownTimer.vue`组件。

## 番茄钟计时器

因此，我们已经有了一个完全功能的倒计时计时器。我们离应用程序的最终目的——能够倒计时任何给定的时间——已经非常接近了。我们只需要基于它实现一个番茄钟计时器。我们的番茄钟计时器必须使用工作番茄钟时间初始化倒计时组件，并在番茄钟结束后将其重置为休息时间。休息结束后，它必须再次将其重置为工作番茄钟时间。依此类推。不要忘记，三个常规番茄钟后的休息时间略长于通常的休息时间。

让我们创建一个`config`文件，其中包含这些值，这样我们就可以在需要用不同的时间测试应用程序时轻松更改它。因此，我们需要指定`workingPomodoro`、`shortBreak`和`longBreak`的值。我们还需要指定到长休息之前工作的*番茄钟*数量。默认情况下，这个值将是三，但是如果你是一个工作狂，你可以在*23485*个常规番茄钟后指定更长的番茄钟休息（不要这样做，我还需要你！）。因此，我们的配置文件是一个常规的`.js`文件，其内容如下：

```js
//src/config.js
export default {
  **workingPomodoro**: 25,
  **shortBreak**: 5,
  **longBreak**: 10,
  **pomodorosTillLongBreak**: 3
}
```

在`PomodoroTimer`组件中导入这个文件。让我们还为这个组件定义必要的数据。因此，番茄钟计时器有三种主要状态；它要么处于工作状态，要么处于短休息状态，要么处于长休息状态。它还应该计算到长休息之前的番茄钟数量。因此，我们的`PomodoroTimer`组件的数据将如下所示：

```js
//PomodoroTimer.vue
data () {
  return {
    isWorking: true,
    isShortBreak: false,
    isLongBreak: false,
    pomodoros: 0
  }
}
```

现在，我们可以根据番茄钟计时器的当前状态计算`time`的值。为此，我们只需要将当前间隔对应的分钟数乘以`60`。我们需要定义哪个间隔是正确的分钟数，并根据应用程序的当前状态做出决定。下面是我们漂亮的计算值的`if-else`构造：

```js
//PomodoroTimer.vue
computed: {
  time () {
    let minutes

    if (this.**isWorking**) {
      minutes = config.**workingPomodoro**
    } else if (this.**isShortBreak**) {
      minutes = config.**shortBreak**
    } else if (this.**isLongBreak**) {
      minutes = config.**longBreak**
    }

    return minutes * 60
  }
}
```

这比较清楚，对吧？现在，我们必须编写代码，以在工作的番茄钟、短休息和长休息之间切换。让我们称这个方法为`togglePomodoro`。这个方法应该做什么？首先，`isWorking`状态应该根据先前的值设置为`true`或`false`（`this.isWorking = !this.isWorking`）。然后，我们应该重置`isShortBreak`和`isLongBreak`的值。然后我们必须检查`isWorking`的状态是否为`false`，这意味着我们目前正在休息。如果是的话，我们必须增加到目前为止完成的番茄数量。然后根据番茄数量，我们需要将其中一个休息状态设置为`true`。这是这个方法：

```js
//PomodoroTimer.vue
methods: {
  togglePomodoro () {
    // toggle the working state
    **this.isWorking = !this.isWorking**

    // reset break states
    **this.isShortBreak = this.isLongBreak = false**

    // we have switched to the working state, just return
    if (this.isWorking) {
      return
    }

    // we have switched to the break state, increase the number of pomodoros and choose between long and short break
    **this.pomodoros ++**
    this.isLongBreak = **this.pomodoros % config.pomodorosTillLongBreak === 0**
    this.isShortBreak = **!this.isLongBreak**
  }
}
```

现在，我们只需要找到一种调用这个方法的方式。它应该在什么时候被调用？很明显，每当倒计时器达到零时，应该调用这个方法，但我们如何能意识到这一点呢？某种程度上，倒计时器组件必须向其父组件通知它已经停在零上。幸运的是，使用 Vue.js，组件可以使用`this.$emit`方法发出事件。因此，我们将从倒计时组件触发此事件，并将其处理程序绑定到从`PomodoroTimer`调用的组件上。让我们称这个事件为`finished`。打开`CountDownTimer.vue`组件，并找到一个地方，我们在那里检查减少的时间戳是否达到了零值。在这一点上，我们必须大喊“嘿，父组件！我完成了我的任务！给我另一个”。这是一个简单的代码：

```js
// CountDownTimer.vue
<...>
if (this.timestamp <= 0) {
  **this.$emit('finished')**
  this.timestamp = this.time
}
```

绑定这个事件非常简单。就像任何其他事件一样；只需在`PomodoroTimer`模板内使用`@`后跟附加到组件的事件名称。

```js
<count-down-timer **@finished="togglePomodoro"** :time="time"></count-down-timer>
```

现在检查应用程序的页面。尝试在配置文件中玩弄时间值。检查一切是否正常工作。

### 锻炼

你已经开始使用新的番茄钟来安排你的日常生活了吗？如果是的话，我相信当计时器在工作时，你会非常愉快地浏览其他标签并做其他事情。你有没有注意到时间比应该的时间长？我们的浏览器真的很聪明；为了不影响你的 CPU，它们在非活动的标签中保持相当空闲。这实际上是完全合理的。如果你不看它们，为什么非活动的标签要执行复杂的计算或者基于`setIntervals`和`setTimeout`函数运行一些疯狂的动画呢？虽然从性能方面来说这是完全合理的，但对我们的应用程序来说并没有太多意义。

不管怎样，它都应该倒数 25 分钟。为了这个练习，改进我们的倒计时器，使其始终倒计时准确的秒数，即使它在隐藏或非活动的浏览器标签中打开。谷歌一下，你会看到整个互联网上关于*Stackoverflow*的结果：

![锻炼](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00085.jpeg)

在非活动标签中使用 setInerval 的奇怪行为充斥着互联网

我还希望你在这个练习中为`CountDownTimer`组件的`time`属性添加一个监视器，以便重新启动计时器。这将使我们能够更精确地在`PomodoroTimer`组件中更改时间时重置计时器。在这方面，请查看 Vue 文档，网址为[`vuejs.org/v2/guide/computed.html#Watchers`](https://vuejs.org/v2/guide/computed.html#Watchers)。

对于这两个任务，请查看`chapter4/8/profitoro`应用程序文件夹，自行检查。唯一应用更改的组件是`CountDownTimer.vue`组件。注意`setInterval`函数以及如何更新`timestamp`。

# 引入锻炼

我写这一章时非常热情，计算正弦、余弦，绘制 SVG，实现计时器，并照顾非活动标签等等，以至于我几乎忘记了做锻炼！我喜欢做平板支撑和俯卧撑，你呢？顺便说一句，你难道也忘了锻炼是我们应用程序的一部分吗？在休息时间，我们应该做简单的锻炼，而不仅仅是查看社交网络！

我们将在接下来的章节中实现完整的锻炼和管理；现在，让我们为锻炼留下一个漂亮的占位符，并在这个占位符中硬编码一个锻炼（我投票支持俯卧撑，因为这本书是我的，但你可以添加你自己喜欢的锻炼或者锻炼）。打开`PomodoroTimer.vue`组件，并将倒计时组件包装在一个带有`row`类的`div`中。我们将使这一行包含两列，其中一列将是倒计时器，另一列是一个有条件渲染的包含锻炼的元素。为什么有条件呢？因为我们只需要在番茄钟休息时显示这个元素。我们将使用`v-show`指令，以便包含元素始终存在，只有`display`属性会改变。因此，标记看起来像下面这样：

```js
//PomodoroTimer.vue
<div class="container">
  <div class="**row**">
    <div **v-show="!isWorking"** class="**col-sm-4**">
      WORKOUT TIME!
    </div>
    <count-down-timer class="**col-sm-8**" @finished="togglePomodoro" :time="time"></count-down-timer>
  </div>
</div>
```

请注意`col-sm-4`和`col-sm-8`。再次强调，我希望在更大的设备上列看起来不同，在小设备上堆叠！

我们应该使用什么元素来显示我们的锻炼？出于某种原因，我非常喜欢 Bootstrap 的`jumbotrons`（[`v4-alpha.getbootstrap.com/components/jumbotron/`](https://v4-alpha.getbootstrap.com/components/jumbotron/)），所以我将使用一个包含锻炼标题的标题元素，锻炼描述的引导元素，以及一个图像元素来显示锻炼图像的`jumbotron`。

### 注意

请注意，Bootstrap 的 Jumbotron 组件的 URL 是 alpha 版本的，下一个版本将在官方网站上提供

因此，我用于显示锻炼的标记结构如下：

```js
//PomodoroTimer.vue
<div class="jumbotron">
  <div class="container">
    <img class="img-fluid rounded" src="IMAGE_SOURCE" alt="">
    <h2>Push-ups</h2>
    <lead>
      Description: lorem ipsum
    </lead>
  </div>
</div>
```

在这一部分，随意添加另一个适合你的好锻炼，这样你就能在读完这本书之前锻炼了。检查`section4/9/profitoro`文件夹中的此部分的代码。

这是我的笔记本电脑屏幕上的番茄钟的样子：

![介绍锻炼](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00086.jpeg)

笔记本电脑屏幕上的番茄钟

这是它在手机屏幕上的样子：

![介绍锻炼](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00087.jpeg)

手机屏幕上的番茄钟

当然，它并不那么美观，但它是响应式和自适应的，我们没有为它做任何 CSS 黑魔法！

# 总结

在本章中，我们做了很多事情。我们实现了我们的番茄钟计时器的主要功能，现在它是完全功能的、可配置的、可用的和响应的。我们启动了我们的 ProFitOro 应用程序，将其分成组件，为每个定义的组件创建了一个骨架，并完全实现了其中的一个。我们甚至重新学习了一些三角学，因为数学无处不在。我们实现了我们的计时器，并让它在隐藏和非活动标签上也能工作。我们使用强大的 Bootstrap 布局类使应用程序对不同设备尺寸具有响应性和适应性。我们的应用程序是功能性的，但离美观还有很大差距。不过，暂时不要在意这些灰色调；让我们暂时坚持它们。在本书的最后，你将得到你漂亮的 ProFitOro 样式，我向你保证！

我们准备继续在技术世界中的旅程。在下一章中，我们将学习如何配置我们的番茄钟，以及如何使用 Firebase 存储配置和使用统计数据。因此，在下一章中我们将：

+   回到 Vuex 集中式状态管理架构，并将其与 Google Firebase 存储系统结合起来，以存储应用程序的关键数据，如配置和统计信息。

+   实现 ProFitOro 的配置

+   实现 ProFitOro 使用统计数据的存储、检索和显示


# 第五章：配置您的番茄钟

在上一章中，我们实现了 ProFitOro 应用程序的主要功能-番茄钟计时器。我们甚至添加了一个硬编码的锻炼，这样我们就可以在休息时间锻炼。实际上，我已经开始使用 ProFitOro。当我写下这些文字时，番茄钟正在倒计时-*滴答滴答滴答滴答*。

在这一章中，我们将探索*Firebase 实时数据库*的可能性及其 API。我们将管理存储、检索和更新应用程序的使用统计和配置。我们将使用 Vuex 存储将应用程序的数据从数据库传递到前端应用程序。

为了将这种可能性带到 UI 中，我们将使用 Vue 的响应性结合 Bootstrap 的强大之处。因此，在这一章中，我们将使用以下内容来实现 ProFitOro 的统计和设置组件：

+   Firebase 实时数据库

+   Vue.js 的响应式数据绑定和 Vuex 状态管理

+   Bootstrap 的强大之处在于使事物具有响应性

# 设置 Vuex 存储

在开始使用数据库中的真实数据之前，让我们为我们的 ProFitOro 设置 Vuex 存储。我们将使用它来管理番茄钟计时器的配置，用户设置（如用户名）以及个人资料图片的 URL。我们还将使用它来存储和检索应用程序的使用统计。

从第二章 *Hello User Explained*，您已经知道了 Vuex 存储的工作原理。我们必须定义代表应用程序状态的数据，然后我们必须提供所有需要的 getter 来获取数据和所有需要的 mutation 来更新数据。一旦所有这些都设置好了，我们就能够从组件中访问这些数据。

应用程序的存储准备就绪并设置好后，我们可以将其连接到实时数据库，并稍微调整 getter 和 mutation 以操作真实数据。

首先，我们需要告诉我们的应用程序将使用 Vuex 存储。为此，让我们为`vuex`添加`npm`依赖项：

```js
**npm install vuex --save**

```

现在，我们需要定义我们存储的基本结构。我们的 Vuex 存储将包含以下内容：

+   **State**：应用程序数据的初始状态。

+   **Getters**：检索状态属性的方法。

+   **Mutations**：提供改变状态的方法。

+   **操作**：可以调度以调用突变的方法。操作和突变之间唯一的区别是操作可以是异步的，我们可能需要它们用于我们的应用程序。

听起来很简单，对吧？只需创建一个名为`store`的文件夹，并为我们刚刚指定的所有内容创建 JavaScript 文件。还要创建`index.js`文件，该文件将使用所有这些内容实例化一个带有所有这些内容的 Vuex 存储。以下是您的结构：

![设置 Vuex 存储](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00088.jpeg)

存储文件夹的结构

当我们在第二章中首次提到 Vuex 存储时，*Hello User Explained*，我们简化了结构，并在同一个文件中介绍了所有存储的组件。现在，我们将遵循良好的模块化结构，并让所有内容都放在自己的位置上。我们甚至可以进一步将状态分离到模块中（一个用于配置，另一个用于设置，依此类推），但对于 ProFitOro 的复杂级别来说，这可能会有些过度。但是，如果您想了解如何将存储分离为逻辑模块，请查看关于 Vuex 的这篇出色文档中有关模块的部分：[`vuex.vuejs.org/en/`](https://vuex.vuejs.org/en/)。

尽管如此，让我们继续使用我们的存储。在创建了结构之后，将所有存储组件导入`index.js`并创建一个 Vuex 实例，将所有这些组件作为参数传递。不要忘记导入 Vuex 并告诉 Vue 使用它！因此，我们的存储入口点将如下所示：

```js
//store/index.js
**import Vue from 'vue'**
**import Vuex from 'vuex'**
import state from './state'
import getters from './getters'
import mutations from './mutations'
import actions from './actions'

**Vue.use(Vuex)**

export default new Vuex.Store({
  **state,**
 **getters,**
 **mutations,**
 **actions**
})
```

现在唯一重要的事情，以便我们的设置完全完成，就是让我们的应用程序知道它现在正在使用这个存储。这样，存储将在所有组件中可用。要使其成为可能的唯一事情就是在应用程序的入口点（`main.js`）中导入我们的存储，并将其传递给 Vue 实例：

```js
//main.js
import Vue from 'vue'
import App from './App'
**import store from './store'**

new Vue({
  el: '#app',
  template: '<App/>',
  components: { App },
  **store**
})
```

现在，我们已经完全准备好开始使用存储进行魔术了。您是否一直在思念编码？好了，现在可以了！让我们首先用存储的状态和获取器替换我们已经创建的`config`文件，该文件用作番茄钟定时属性的容器。只需将`config`文件的所有配置元素复制到我们的状态中，并为其创建一个获取器：

```js
//store/state.js
const config = {
  workingPomodoro: 25,
  shortBreak: 5,
  longBreak: 10,
  pomodorosTillLongBreak: 3
}

export default {
  **config**
}
```

让我们现在转向 getter。 Getter 不仅仅是普通的函数。在幕后，它们接收状态作为参数，因此您可以访问应用程序状态的数据，而无需进行任何依赖注入的努力，因为 Vuex 已经为您管理了。因此，只需创建一个接收状态作为参数并返回任何状态数据的函数！如果需要，在 getter 内部，您可以对数据执行任何操作。因此，`config`文件的 getter 可能看起来像这样：

```js
//store/getters.js
function getConfig (state) {
  return state.config
}
```

由于我们使用的是 ES6，可以以更简洁和优雅的方式重写：

```js
//store/getters.js
var getConfig = (state) => state.config
```

然后，它可以被导出：

```js
//store/getters.js
export default {
  getConfig: getConfig
}
```

或者，我们可以简单地使用：

```js
//store/getter.js
export default {
  getConfig
}
```

整个事情实际上可以写成：

```js
//store/getters.js
export default {
  **getConfig: state => state.config**
}
```

多么惊人简单啊？当我开始使用 JavaScript 时（不要问我什么时候，我不想让自己感觉老），我几乎无法想象这样的语法会有可能。

现在，您可以在任何应用程序组件中使用您的新 getter。如何？您还记得使用`this.$store.state`属性轻松访问状态有多容易吗？同样，在计算数据函数内部，您可以访问您的“getter”：

```js
**computed**: {
  config () {
    return **this.$store.getters.getConfig**
  }
},
```

从现在开始，`this.config`可以在组件的所有计算值和方法中使用。现在想象一下，在同一个组件内，我们需要使用多个 getter。例如，假设我们为每个 config 的值创建 getter。因此，对于每个值，您都必须重复这种繁琐的代码：`this.$store.getters.bla-bla-bla`。啊！一定有更简单的方法...而且确实有。Vuex 很友好地为我们提供了一个名为`mapGetters`的辅助对象。如果您简单地将此对象导入到组件中，就可以使用 ES6 扩展运算符使用`mapGetters`调用您的 getter：

```js
import { **mapGetters** } from 'vuex'

export default {
  computed: {
    **...mapGetters**([
      'getConfig'
    ])
  }
}
```

或者，如果您想将 getter 方法映射到其他名称，只需使用一个对象：

```js
import { mapGetters } from 'vuex'

export default {
  computed: {
    ...mapGetters({
      **config: 'getConfig'**
    })
  }
}
```

所以，这就是我们要做的。我们将在`PomodoroTimer`组件内部使用`mapGetters`助手，并删除对导入的`config`文件的引用（还要记得删除文件本身；我们不希望代码库中有死代码）。我们将用`this.config`替换所有对`config`的引用。因此，我们的`PomodoroTimer`脚本部分将如下所示：

```js
//PomodoroTimer.vue
<script>
  // ...
  **import { mapGetters } from 'vuex'**
  // ...
  export default {
    data () {
      // ...
    },
    computed: {
      **...mapGetters({**
 **config: 'getConfig'**
 **})**,
      time () {
        let minutes
        if (this.isWorking) {
          minutes = **this.config**.workingPomodoro
        } else if (this.isShortBreak) {
          minutes = **this.config**.shortBreak
        } else if (this.isLongBreak) {
          minutes = **this.config**.longBreak
        }

        return minutes * 60
      }
    },
    // ...
    methods: {
      togglePomodoro () {
        // ...
        this.isLongBreak = this.pomodoros % **this.config**.pomodorosTillLongBreak === 0
      }
    }
  }
</script>
```

检查你的页面，一切都应该和以前一样。这种新方法的优势是什么？——有人可能会问，我们已经在这里花了半章的时间设置这个商店和它的方法、获取器、操作，等等…最后，我们得到了完全相同的行为。为什么？嗯，你还记得这一章的整个目的是能够配置和重新配置番茄工作法的定时设置，并将它们存储在数据库中吗？如果我们不得不在我们的组件中引入数据库引用和检索和存储数据的所有操作，我们的生活会更加艰难。想象一下，如果某个时候 Firebase 不符合你的需求，你希望切换到另一个数据源，甚至是另一种技术，比如 *Elasticsearch* 或者 *MongoDB*。你将不得不改变你的组件和它的方法，以及它的计算值。维护所有这些不是听起来像地狱吗？

让你的数据驻留在存储中，并且让你的获取器负责检索它们，将使你只需要改变你的获取器，如果你决定改变底层数据源。你的组件将永远不会被触及！这是你的应用程序的数据和逻辑层的抽象。在软件工程领域，抽象是一件非常酷的事情。

让我们为 `Settings.vue` 组件定义一个基本的标记。检查我们的模拟。

这个组件将包含两个主要区域：

+   个人设置配置区域

+   番茄工作法定时设置配置区域

同样，我将使用 Bootstrap 栅格类来帮助我构建一个漂亮的、响应式的布局。我希望在小设备上制作两个堆叠列，在中等大小的设备上制作两个相同大小的列，在大设备上制作两个不同大小的列。因此，我将使用 `row` 类来包装 `div` 和相应的 `col-*-*` 类来包装我们 `Settings` 组件的两个主要区域。

```js
// Settings.vue
<div class="**row justify-content-center**">
  <div class="**col-sm-12 col-md-6 col-lg-4**">
    <div class="container">
      <h2>Account settings</h2>
      account settings
    </div>
  </div>
  <div class="**col-sm-12 col-md-6 col-lg-8**">
    <div class="container">
      <h2>Set your pomodoro timer</h2>
      pomodoro timer configuration
    </div>
  </div>
</div>
```

现在让我们只集中在番茄工作法定时设置配置上。我创建了一个名为 `SetTimer.vue` 的组件。这个组件只包含一个数字类型的输入，并在其值发生变化时发出一个方法。在番茄工作法设置容器中，我将使用从导入的 `mapGetters` 助手中获取的不同值，将这个组件渲染三次：

```js
//Settings.vue
<template>
  <...>
    <div class="row justify-content-center align-items-center">
      <div class="col-md-5 col-sm-10">
        **<set-timer :value="config.workingPomodoro"></set-timer>**
        <div class="figure-caption">Pomodoro</div>
      </div>
      <div class="col-md-4 col-sm-10">
        **<set-timer :value="config.longBreak"></set-timer>**
        <div class="figure-caption">Long break</div>
      </div>
      <div class="col-md-3 col-sm-10">
        **<set-timer :value="config.shortBreak"></set-timer>**
        <div class="figure-caption">Short break</div>
      </div>
    </div>
  <...>
</template>
```

通过一些 CSS 魔法，我能够在 `SetTimer` 组件中渲染三个输入圆圈，如下所示：

![设置一个 Vuex 存储](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00089.jpeg)

输入允许我们为不同的番茄钟间隔设置定时器的球

您可以在`chapter5/1/profitoro`文件夹中找到相应的代码。特别是检查`components/main/sections/timer`文件夹中的`SetTimer.vue`组件以及在`Settings.vue`组件中如何使用相应的值调用它。

# 定义操作和突变

很棒，我们的组件现在可以从存储中获取数据，但如果我们的组件也能够更改存储中的数据，那可能会更有趣。另一方面，我们都知道我们不能直接修改存储的状态。

状态不应该被任何组件触摸。然而，您还记得我们关于 Vuex 存储的章节中有一些特殊函数可以改变存储。它们甚至被称为`mutations`。这些函数可以对 Vuex 存储数据做任何它们/你想做的事情。这些突变可以使用应用于存储的`commit`方法来调用。在底层，它们实质上接收两个参数 - 状态和值。

我将定义三个突变 - 分别用于定时器的每个定义。这些突变将使用新值更新`config`对象的相应属性。因此，我的突变如下：

```js
//store/mutations.js
export default {
  **setWorkingPomodoro** (state, workingPomodoro) {
    state.config.workingPomodoro = workingPomodoro
  },
  **setShortBreak** (state, shortBreak) {
    state.config.shortBreak = shortBreak
  },
  **setLongBreak** (state, longBreak) {
    state.config.longBreak = longBreak
  }
}
```

现在我们可以定义操作。操作基本上会调用我们的突变，因此可以被视为重复的工作。然而，请记住操作和突变之间的区别在于操作实际上可以是异步的，因此当我们将操作连接到数据库时可能会派上用场。现在，让我们告诉操作在提交之前验证接收到的值。`actions`方法接收存储和一个新值。由于存储为我们提供了一个名为`commit`的基本方法，该方法将调用所需的突变的名称，因此我们可以定义每个操作如下：

```js
actionName (**{commit}**, newValue) {
  **commit**('mutationName', newValue)
}
```

### 提示

我们可以将`{commit}`写为参数，并立即使用`commit`函数，因为我们使用的是 ES6 和对象解构对我们来说非常完美（[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment)）。

因此，我的操作看起来是这样的：

```js
//store/actions.js
export default {
  **setWorkingPomodoro** ({commit}, workingPomodoro) {
    if (workingPomodoro) {
      commit('setWorkingPomodoro', parseInt(workingPomodoro, 10))
    }
  },
  **setShortBreak** ({commit}, shortBreak) {
    if (shortBreak) {
      commit('setShortBreak', parseInt(shortBreak, 10))
    }
  },
  **setLongBreak** ({commit}, longBreak) {
    if (longBreak) {
      commit('setLongBreak', parseInt(longBreak, 10))
    }
  }
}
```

现在，让我们回到`Settings.vue`组件。这个组件应该导入操作并在需要时调用它们，对吧？我们如何导入操作？你还记得`mapGetters`助手吗？有一个类似的助手用于操作，叫做`mapActions`。所以，我们可以和`mapGetters`助手一起导入它，并在`methods`对象内使用扩展操作符(`…`)：

```js
//Settings.vue
<script>
  import {mapGetters, **mapActions**} from 'vuex'
  <...>
  export default {
    <...>
    methods: {
      **...mapActions(['setWorkingPomodoro', 'setShortBreak', 'setLongBreak'])**
    }
  }
</script>
```

现在，我们必须在`set-timer`输入框的值发生变化时调用所需的操作。在前一段中，我们讨论了`SetTimer`组件发出`changeValue`事件。所以，我们现在唯一需要做的就是将这个事件绑定到所有三个`set-timer`组件上，并调用相应的方法：

```js
<div class="col-md-5 col-sm-10">
  **<set-timer :value="config.workingPomodoro" @valueChanged="setWorkingPomodoro"></set-timer>**
  <div class="figure-caption">Pomodoro</div>
</div>
<div class="col-md-4 col-sm-10">
  **<set-timer :value="config.longBreak" @valueChanged="setLongBreak"></set-timer>**
  <div class="figure-caption">Long break</div>
</div>
<div class="col-md-3 col-sm-10">
  **<set-timer :value="config.shortBreak" @valueChanged="setShortBreak"></set-timer>**
  <div class="figure-caption">Short break</div>
</div>
```

打开页面，尝试更改每个计时器设置的值。

如果你正在使用 Chrome 浏览器，但还没有安装 Vue 开发者工具，请安装它。你会看到它是多么方便和可爱！只需按照这个链接：[`goo.gl/22khXD`](https://goo.gl/22khXD)。

安装了 Vue devtools 扩展后，你会立即看到这些值在 Vuex 存储中是如何变化的：

![定义操作和变异](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00090.jpeg)

一旦输入框中的值发生变化，它们就会立即在 Vuex 存储中发生变化

检查`chapter5/2/profitoro`文件夹中的本节最终代码。注意存储文件夹内的`actions.js`和`mutations.js`文件以及`Settings.vue`组件。

# 建立一个 Firebase 项目

我希望你还记得如何从本书的前几章中设置 Firebase 项目。在[`console.firebase.google.com`](https://console.firebase.google.com)打开你的 Firebase 控制台，点击**添加项目**按钮，命名它，并选择你的国家。Firebase 项目已准备好。是不是很容易？现在让我们准备我们的数据库。以下数据将存储在其中：

+   **配置**: 我们的 Pomodoro 计时器值的配置

+   **统计**: Pomodoro 使用的统计数据

每个这些对象将通过一个特殊的键来访问，该键将对应于用户的 ID；这是因为在下一章中，我们将实现一个身份验证机制。

配置对象将包含值-`workingPomodoro`，`longBreak`和`shortBreak`-这些值对我们来说已经很熟悉了。

让我们向我们的数据库添加一个带有一些虚假数据的配置对象：

```js
{
  "configuration": {
    "test": {
      "workingPomodoro": 25,
      "shortBreak": 5,
      "longBreak": 10
    }
  }
}
```

你甚至可以将其创建为一个简单的 JSON 文件并导入到你的数据库中：

![设置 Firebase 项目](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00091.jpeg)

将 JSON 文件导入到您的实时 Firebase 数据库

恭喜，您的实时数据库已准备就绪！请记住，默认情况下，安全规则不允许您从外部访问数据，除非您经过身份验证。现在，让我们暂时删除这些规则。一旦我们实现了身份验证机制，我们将稍后添加它们。单击**RULES**选项卡，并用以下对象替换现有规则：

```js
{
  "rules": {
    ".read": true,
    ".write": true
  }
}
```

现在我们可以从我们的 Vue 应用程序访问我们的实时数据库。

# 将 Vuex 存储连接到 Firebase 数据库

现在，我们必须将我们的 Vuex 存储连接到 Firebase 数据库。我们可以使用本机 Firebase API 将状态数据绑定到数据库数据，但是如果有人已经为我们做了这些事情，为什么我们要处理承诺和其他东西呢？这个人叫 Eduardo，他创建了 Vuexfire - Vuex 的 Firebase 绑定（[`github.com/posva/vuexfire`](https://github.com/posva/vuexfire)）。如果您在*Wroclaw*的*vueconf2017 大会*上，您可能还记得这个家伙：

![将 Vuex 存储连接到 Firebase 数据库](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00092.jpeg)

Eduardo 在 Vue 大会期间谈到 Vue 和 Firebase

Vuexfire 带有 Firebase 的 mutations 和 actions，这将为您执行所有幕后工作，而您只需在 mutations 和 actions 对象中导出它们。因此，首先安装`firebase`和`vuexfire`：

```js
**npm install vue firebase vuexfire –save**

```

在您的存储的`index.js`入口点中导入`firebase`和`firebaseMutations`：

```js
//store/index.js
import firebase from 'firebase'
import { firebaseMutations } from 'vuexfire'
```

现在，我们需要获取对 Firebase 应用程序的引用。Firebase 带有一个初始化方法`initializeApp`，它接收由许多应用程序设置数据组成的对象 - 应用程序 ID，身份验证域等。现在，我们至少必须提供数据库 URL。要获取数据库 URL，只需转到您的 Firebase 项目设置，然后单击**将 Firebase 添加到您的 Web 应用**按钮：

![将 Vuex 存储连接到 Firebase 数据库](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00093.jpeg)

单击“将 Firebase 添加到您的 Web 应用”按钮

复制数据库 URL，甚至整个配置对象，并将其粘贴到您的存储的`index.js`文件中：

```js
//store/index.js
let app = firebase.initializeApp({
  databaseURL: **'https://profitoro-ad0f0.firebaseio.com'**
})
```

您现在可以获取配置对象的引用。一旦我们实现了身份验证机制，我们将使用经过身份验证的用户 ID 从数据库中获取当前用户的配置。现在，让我们使用我们硬编码的 ID `test`：

```js
let configRef = app.database().ref('**/configuration/test**')
```

我将使用扩展运算符在状态对象中导出`configRef`引用。因此，这个引用可以被动作访问：

```js
//store/index.js
export default new Vuex.Store({
  **state: {**
 **...state,**
 **configRef**
 **}**
})
```

为了使整个 Vuexfire 魔术生效，我们还必须在`mutations`对象中导出`firebaseMutations`：

```js
//store/index.js
export default new Vuex.Store({
  mutations: {
    ...mutations,
    **...firebaseMutations**
  },
  actions
})
```

因此，我们整个`store/index.js`现在看起来像下面这样：

```js
//store/index.js
import Vue from 'vue'
import Vuex from 'vuex'
import state from './state'
import getters from './getters'
import mutations from './mutations'
import actions from './actions'
import firebase from 'firebase'
import { firebaseMutations } from 'vuexfire'
Vue.use(Vuex)

// Initialize Firebase
let config = {
  databaseURL: 'https://profitoro-ad0f0.firebaseio.com'
}
let app = firebase.initializeApp(config)
let configRef = app.database().ref('/configuration/test')

export default new Vuex.Store({
  state: {
    ...state,
    configRef
  },
  getters,
  mutations: {
    ...mutations,
    ...firebaseMutations
  },
  actions
})
```

现在让我们去我们的动作。非常重要的是，在做任何其他事情之前，我们要将我们的数据库引用绑定到相应的状态属性上。在我们的情况下，我们必须将状态的`config`对象绑定到它对应的引用`configRef`上。为此，我们的朋友 Eduardo 为我们提供了一个叫做`firebaseAction`的动作增强器，它实现了`bindFirebaseRef`方法。只需调用这个方法，你就不必担心承诺和它们的回调。

打开`action.js`并导入`firebaseAction`增强器：

```js
//store/actions.js
import { **firebaseAction** } from 'vuexfire'
```

现在让我们创建一个名为`bindConfig`的动作，我们将使用`bindFirebaseRef`方法实际绑定两个东西在一起：

```js
//store/actions.js
**bindConfig**: firebaseAction(({bindFirebaseRef, state}) => {
  **bindFirebaseRef('config', state.configRef)**
})
```

这个动作应该在什么时候派发呢？可能是在`Settings.vue`组件创建时，因为这个组件负责渲染`config`状态。因此，在`Settings.vue`内部，我们绑定了`created`组件的状态，并在其中调用了`bindConfig`动作：

```js
//Settings.vue
export default {
 //...
 methods: {
    ...mapActions(['setWorkingPomodoro', 'setShortBreak', 'setLongBreak', **'bindConfig'**])
  },
  **created () {**
 **this.bindConfig()**
 **}**
}
```

如果你现在打开页面，你会发现一切都保持不变。唯一的区别是，现在我们使用的数据来自我们的实时数据库，而不是硬编码的`config`对象。您可以通过完全删除状态存储对象内`config`对象的内容并确保一切仍然正常工作来进行检查。

如果你尝试更改输入值，然后刷新页面，你会发现应用的更改没有保存。这是因为我们没有更新数据库引用。所以让我们更新它！好处是我们不需要在组件内部改变*任何*东西；我们只需要稍微改变我们的*动作*。我们将在引用上调用`update`方法。请查看 Firebase 实时数据库文档以了解读取和写入数据：[`firebase.google.com/docs/database/web/read-and-write`](https://firebase.google.com/docs/database/web/read-and-write)。

因此，我们将`state`对象传递给每个动作，并在`state.configRef`上调用`update`方法，将相应的更改属性传递给它。因此，它可能看起来就像以下代码片段一样简单：

```js
//store/actions.js
setWorkingPomodoro ({commit, **state**}, workingPomodoro) {
  **state.configRef.update({workingPomodoro})**
},
```

不要忘记执行所需的检查，将更新的属性解析为整数，并检查`configRef`是否可用。如果不可用，只需使用相应的 mutation 名称调用`commit`方法。检查`chapter5/3/profitoro`文件夹中此部分的最终代码。特别注意`store/index.js`和`store/actions.js`文件以及`Settings.vue`组件。

如果您打开页面并更改番茄钟计时器的值，并继续查看 Firebase 控制台数据库选项卡，您将立即看到差异！

![将 Vuex 存储连接到 Firebase 数据库](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00094.jpeg)

应用于番茄钟计时器配置框的更改立即传播到实时数据库

如果直接在数据库中更改值，您还将看到更改立即传播到您的视图。

# 练习

您已经学会了如何将实时 Firebase 数据库连接到您的 Vue 应用程序，并利用这些知识来更新番茄钟计时器的配置。现在，将您的知识应用到统计领域。为了简单起见，只显示自用户开始使用该应用以来执行的番茄钟总数。为此，您需要执行以下操作：

1.  在您的 Firebase 数据库中添加另一个名为`statistics`的对象，其中包含初始等于`0`的`totalPomodoros`属性。

1.  在存储的`state`中创建一个条目来保存统计数据。

1.  使用`firebaseAction`增强器和`bindFirebaseRef`方法将统计状态对象的`totalPomodoros`映射到 Firebase 引用。

1.  创建一个动作，将更新`totalPomodoros`的引用。

1.  每当必须在`PomodoroTimer`组件内调用此动作时调用此动作。

1.  在`Statistics.vue`组件内显示此值。

尝试自己做。这不应该很困难。遵循我们在`Settings.vue`组件中应用的相同逻辑。如果有疑问，请查看`chapter5/4/profitoro`文件夹，特别是存储的文件 - `index.js`，`state.js`和`actions.js`。然后查看相应的动作如何在`PomodoroTimer`组件内使用，以及它如何在`Statistics`组件中呈现。祝你好运！

# 总结

在本章中，您学会了如何在 Vue 应用程序中使用实时 Firebase 数据库。您学会了如何使用 Vuexfire 及其方法，将我们的 Vuex 存储状态正确地绑定到数据库引用。我们不仅能够从数据库中读取和渲染数据，还能够更新数据。因此，在本章中，我们看到了 Vuex、Firebase 和 Vuexfire 的实际应用。我想我们应该为自己感到自豪。

然而，让我们不要忘记，我们已经在获取用户数据时使用了一个硬编码的用户 ID。此外，我们还不得不通过更改安全规则来向世界公开我们的数据库，这似乎也不太对。看来是时候启用认证机制了！

在下一章中我们将完成这个任务！在下一章中，我们将学习如何使用 Firebase 认证框架来设置认证机制。我们将学习如何在我们的应用程序中使用它，使用 Vuefire（Vue 的 Firebase 绑定：[`github.com/vuejs/vuefire`](https://github.com/vuejs/vuefire)）。我们还将实现我们应用程序的初始视图，负责提供注册和登录的方式。我们将使用 Bootstrap 表单元素，以使屏幕对所有屏幕尺寸响应和适应。所以，让我们继续下一章吧！不要忘记先做一些俯卧撑！
