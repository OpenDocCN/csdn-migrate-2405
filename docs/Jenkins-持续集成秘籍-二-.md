# Jenkins 持续集成秘籍（二）

> 原文：[`zh.annas-archive.org/md5/B61AA47DB2DCCD9DEF9EF3E145A763A7`](https://zh.annas-archive.org/md5/B61AA47DB2DCCD9DEF9EF3E145A763A7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：构建软件

本章中，我们将介绍以下内容：

+   在 Jenkins 中绘制替代代码指标图

+   通过 Maven 运行 Groovy 脚本

+   操纵环境变量

+   通过 Maven 在 Groovy 中运行 Ant

+   基于 JSP 语法错误使 Jenkins 作业失败

+   为集成测试配置 Jetty

+   使用 Rat 查看许可证违规情况

+   在 Maven 中审查许可证违规

+   通过构建描述公开信息

+   通过 groovy-postbuild 插件对生成的数据做出反应

+   通过 Jenkins API 远程触发作业

+   自适应站点生成

# 介绍

本章回顾了 Jenkins 和 Maven 构建之间的关系，还包含了一些使用 Groovy 和 Ant 进行脚本编写的内容。

Jenkins 是灵活性的大师。它在多个平台和技术上表现出色。Jenkins 具有直观的界面和清晰的配置设置。这对完成工作很有帮助。然而，同样重要的是，您清楚地定义 Jenkins 插件与 Maven 构建文件之间的界限。缺乏区分会使您不必要地依赖于 Jenkins。如果您知道您将始终通过 Jenkins 运行构建，则可以放置一些核心工作在 Jenkins 插件中，获得有趣的额外功能。

然而，如果您希望始终能够直接构建、测试和部署，那么您将需要保持`pom.xml`中的细节。您必须权衡利弊；拥有“功能蔓延”是很容易的。与编写冗长的`pom.xml`文件相比，UI 更容易配置。提高的可读性会导致较少的与配置相关的缺陷。对于您来说使用 Jenkins 完成大多数常见任务，如传输工件、通信和绘制测试趋势，也更加简单。Jenkins 与 Maven 之间的互动示例是使用 Jenkins Publish Over SSH 插件（[`wiki.jenkins-ci.org/display/JENKINS/Publish+Over+SSH+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Publish+Over+SSH+Plugin)）。您可以配置传输文件或将以下内容添加到`pom.xml`中：

```
<build>
<plugins>
  <plugin>
    <artifactId>maven-antrun-plugin</artifactId>
    <configuration>
      <tasks>
        <scp file="${user}:${pass}@${host}:${file.remote}" localTofile="${file.local}"/>
      </tasks>
    </configuration>
    <dependencies>
      <dependency>
        <groupId>ant</groupId>
        <artifactId>ant-jsch</artifactId>
        <version>1.6.5</version>
      </dependency>
      <dependency>
        <groupId>com.jcraft</groupId>
        <artifactId>jsch</artifactId>
        <version>0.1.42</version>
      </dependency>
    </dependencies>
  </plugin>
</plugins>
</build>
```

记住特定 JAR 和版本的依赖关系，有时使用 Maven 插件会感觉像魔术一样。Jenkins 插件简化了细节。

Maven 使用配置文件，以便您可以在项目中使用不同的配置，例如开发、验收或生产服务器名称。这还允许您更新插件的版本号，从而简化维护工作。有关更多信息，请访问 [`maven.apache.org/guides/introduction/introduction-to-profiles.html`](http://maven.apache.org/guides/introduction/introduction-to-profiles.html)。

在本章后面，您将有机会使用 AntBuilder 运行 Groovy 脚本。每种方法都是可行的；使用取决于您的偏好而不是一个明确的选择。

Jenkins 插件可以很好地协同工作。例如，推广构建插件（[`wiki.jenkins-ci.org/display/JENKINS/Promoted+Builds+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Promoted+Builds+Plugin)）在构建满足某些条件时发出信号，并在成功构建旁边放置一个图标，如下截图所示：

![Introduction](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_01.jpg)

你可以使用此功能来发出信号，例如，通知质量保证团队需要测试构建，或者通知系统管理员收集构件并部署。其他插件也可以通过推广触发（例如，当开发人员使用推广插件签署构建时），包括 SSH 插件。然而，Maven 不知道推广机制。随着 Jenkins 的发展，预计会有更多的插件相互关系。

Jenkins 精通操作的编排。你应该将作业的运行时间最小化，并将较重的作业偏移到节点上。较重的作业往往聚集在文档生成或测试周围。Jenkins 允许你将作业链接在一起，因此作业将与特定的 Maven 目标相结合，例如集成测试（[`Maven.apache.org/guides/introduction/introduction-to-the-lifecycle.html#Lifecycle_Reference`](http://Maven.apache.org/guides/introduction/introduction-to-the-lifecycle.html#Lifecycle_Reference)）。在这种情况下，你可以选择编写一些构建文件，也许是一个多模块项目（[`maven.apache.org/guides/mini/guide-multiple-modules.html`](http://maven.apache.org/guides/mini/guide-multiple-modules.html)），或者是一个更厚的`pom.xml`文件，其中包含不同的目标，可以在作业之间调用。**保持简单傻瓜**（**KISS**）倾向于决策朝着一个较大的单一文件。

## Jenkins 是一个企业友好的技术中立平台。

Jenkins 是技术中立的，可以将组织、开发团队和软件在生命周期中的位置的项目技术粘合在一起。Jenkins 让你可以运行自己选择的脚本语言，轻松地使用 Git、子版本、CVS 和许多其他版本控制系统拉取源代码。如果 Jenkins 不兼容，开发人员可以通过一点实践编写自己的集成。

在本书中，你将看到涉及到子版本和 GIT 项目。这代表了一个现实的混合。许多人认为 Git 比子版本更加灵活多变。请放心在本书的示例中选择 Git 作为你的存储库。从一开始就设计，Jenkins 使你可以轻松选择不同的版本控制系统。

### 注

如果你看一下 2014 年初 Ohoh 的代表性集合中 Git 和子版本的相对使用情况，对于 Git，有 247,103 个存储库（总数的 37%），子版本有 324,895 个存储库（总数的 48%）。

典型企业在使用最现代化的服务时落后于小型组织，因为他们不愿改变工作流程。因此，预计与较小组织相比，这类企业的子版本仓库比例较高。

## 一个 pom.xml 模板

本章中的配方将包括`pom.xml`示例。为节省页面空间，只显示必要的细节。您可以从书籍网站下载完整的示例。

这些示例是针对 Maven 3.2.1 进行测试的，尽管这些示例应该与最新版本的 Maven 一起工作。

从主 Jenkins 配置屏幕（`http://localhost:8080/configure`）下的**Maven**部分，您将需要安装此版本，并为其提供标签`3.2.1`。

要为 Maven 项目生成基本模板，您有两个选择。您可以通过原型目标（[`Maven.apache.org/guides/introduction/introduction-to-archetypes.html`](http://Maven.apache.org/guides/introduction/introduction-to-archetypes.html)）创建项目，或者您可以从这里开始一个简单的`pom.xml`文件：

```
<project 

xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://Maven.apache.org/maven-v4_0_0.xsd">
<modelVersion>4.0.0</modelVersion>
<groupId>org.berg</groupId>
<artifactId>ch3.builds.xxx</artifactId>
<version>1.0-SNAPSHOT</version>
<name>Template</name>
</project>
```

模板看起来简单，但只是较大有效`pom.xml`的一部分。它与 Maven 中隐藏的默认值相结合。要查看扩展版本，您需要运行以下命令：

```
mvn help:effective-pom

```

除非另有说明，否则应将配方中提到的片段插入模板中，就在`</project>`标签之前，根据约定更新您的`groupID`、`artifactID`和`version`值。有关更多详细信息，请访问[`maven.apache.org/guides/mini/guide-naming-conventions.html`](http://maven.apache.org/guides/mini/guide-naming-conventions.html)。

## Maven 变更

Maven 2 已经结束其生命周期（[`maven.apache.org/maven-2.x-eol.html`](http://maven.apache.org/maven-2.x-eol.html)），开发团队已经停止支持它。您不能指望及时删除新发现的错误。在撰写本书时，Maven 4 正在规划中，尚未发布。

如果您已经安装了作为软件包的 Maven 2，并希望升级到 Maven 3，则需要安装 Maven 软件包。要在不同 Maven 版本之间切换，您需要运行以下 Ubuntu 命令：

```
sudo update-alternatives --config mvn

```

## 设置文件系统 SCM

在前几章中，您使用了将文件复制到工作区的配方。这很容易解释，但受操作系统特定。您还可以通过文件系统 SCM 插件（[`wiki.jenkins-ci.org/display/JENKINS/File+System+SCM`](https://wiki.jenkins-ci.org/display/JENKINS/File+System+SCM)）进行文件复制，因为这是与操作系统无关的。您需要安装该插件，并确保文件具有正确的权限，以便 Jenkins 用户可以复制它们。在 Linux 中，考虑将文件放在 Jenkins 主目录`/var/lib/jenkins`下。

# 在 Jenkins 中绘制替代代码度量

本篇介绍了如何使用绘图插件绘制自定义数据（[`wiki.jenkins-ci.org/display/JENKINS/Plot+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Plot+Plugin)）。这使您可以通过可视化方式展示数值构建数据。

Jenkins 有许多插件可以创建由构建生成的测试结果的视图。分析收集器插件从这些插件中汇总结果以创建聚合摘要和历史记录（[`wiki.jenkins-ci.org/display/JENKINS/Analysis+Collector+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Analysis+Collector+Plugin)）。这非常适合绘制标准结果类型的历史记录，如 JUnit、JMeter、FindBugs 和 NCSS。还有一个 SonarQube 插件（[`docs.codehaus.org/display/SONAR/Jenkins+Plugin`](http://docs.codehaus.org/display/SONAR/Jenkins+Plugin)）支持将数据推送到 SonarQube（[`www.sonarsource.org/`](http://www.sonarsource.org/)）。SonarQube 专注于报告项目的代码质量。然而，尽管选项很多，但可能会有一天你需要绘制自定义结果。

假设你想了解在集成测试期间你的自定义缓存中生成了多少次命中或未命中的历史记录。通过构建的绘图可以让你了解代码的变化是改善还是降低了性能。数据是伪造的：一个简单的 Perl 脚本会生成随机结果。

## 准备工作

在 Jenkins 的插件**管理器**部分（`http://localhost:8080/pluginManager/available`），安装绘图插件。创建一个名为`ch3.building_software/plotting`的目录。

## 如何操作...

1.  创建`ch3.building_software/plotting/hit_and_miss.pl`文件，并添加以下代码行：

    ```
    #!/usr/bin/perl
    my $workspace = $ENV{'WORKSPACE'};

    open(P1, ">$workspace/hits.properties")|| die;
    open(P2, ">$workspace/misses.properties")|| die;
    print P1 "YVALUE=".rand(100);
    print P2 "YVALUE=".rand(50);
    ```

1.  创建一个自由样式的作业，**作业名称**为`ch3.plotting`。

1.  在**源代码管理**部分，勾选**文件系统**，并在**路径**字段中添加你的绘图目录的完全限定路径，例如`/var/lib/jenkins/cookbook/ch3.building_software/plotting`。

1.  在**构建**部分，为**执行 Shell**选择**添加构建步骤**，或者在 Windows 系统中，选择**执行 Windows**批处理命令。

1.  对于命令，添加`perl hit_and_miss.pl`。

1.  在**后构建操作**部分，选中**绘制构建数据**复选框。

1.  将以下值添加到新扩展区域：

    +   **绘图组**：`缓存数据`

    +   **绘图标题**：`命中和未命中`

    +   **绘图 y 轴标签**：`命中或未命中的次数`

    +   **绘图样式**：**堆积面积**

1.  在**数据系列文件**中输入`misses.properties`，在**数据系列图例**标签中输入`Misses`。

1.  在**数据系列文件**中输入`hits.properties`，在**数据系列图例**标签中输入`Hits`。

1.  在配置页面底部，点击**保存**按钮，如下图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_02.jpg)

1.  多次运行该作业。

1.  查看**Plot**链接，你会看到类似以下截图：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_03.jpg)

## 它是如何工作的...

Perl 脚本生成两个属性文件：`hits`和`misses`。 `hits`文件包含介于 0 和 100 之间的`YVALUE`，而`misses`文件包含介于`0`和 50 之间的`YVALUE`。这些数字是随机生成的。然后绘图插件从`YVALUE`属性中读取值。

两个属性文件被绘图插件读取。该插件跟踪历史记录，它们的值显示在趋势图中。你将不得不尝试不同的图形类型，找到最佳的绘图方法来适应自定义测量。

目前有两种其他数据格式可供使用：XML 和 CSV。然而，在在线帮助清楚解释所使用的结构之前，我建议仍然使用属性格式。

选择 Perl 的原因是其编码简洁和跨平台特性。该脚本也可以用 Groovy 编写，并在 Maven 项目中运行。你可以在*通过 Maven 运行 Groovy 脚本*方法中看到一个 Groovy 示例。

## 更多信息...

绘图插件允许选择多种绘图类型，包括**区域**、**条形**、**条形 3D**、**线条**、**线条 3D**、**堆叠区域**、**堆叠条形**、**堆叠条形 3D**和**瀑布**。如果选择正确的图形类型，可以生成漂亮的图形。

如果想将这些自定义图形添加到报告中，必须保存它们。您可以通过在浏览器中右键单击图像来完成。

你可能希望有不同大小的图形。你可以通过访问`http://host/job/JobName/plot/getPlot?index=n&width=x&height=y`生成图像。

`[Width]`和`[height]`参数定义了图形的大小。 `n`是指向特定图表的索引号。如果只有一个图表，那么`n=0`。如果配置了两个图表，那么`n`可以是 0 或 1。要发现索引，请访问图表的链接，并检查**跳转到**下拉菜单，从中选择最高的**图表**编号之一，如下截图所示：

![更多信息...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_04.jpg)

要根据本方法中的作业生成尺寸为 800 x 600 的 PNG 格式图形，可以使用类似`localhost:8080/job/ch3.plotting/plot/getPlot?index=0&width=800&height=600`的 URL。

### 提示

欲下载图像而不登录自己，请使用*通过 Jenkins API 远程触发作业*方法中提到的可脚本化身份验证方法。

## 参见

+   *通过 Maven 运行 Groovy 脚本*方法

+   *自适应站点生成*方法

+   *通过 Jenkins API 远程触发作业*方法

# 通过 Maven 运行 Groovy 脚本

本方法描述如何使用 GMaven 插件（[`docs.codehaus.org/display/GMAVEN/Home`](http://docs.codehaus.org/display/GMAVEN/Home)）运行 Groovy 脚本。

在构建中运行 Groovy 脚本的能力可以让您在 Maven 和 Jenkins 中始终使用同一种脚本语言。Groovy 可以在任何 Maven 阶段运行。有关详细信息，请参阅本篇中*关于 Maven 阶段*部分。

Maven 可以从构建文件内部执行 Groovy 源代码，也可以在另一个文件位置或从远程 Web 服务器执行。

### 注意

另一种插件是 GMavenPlus。要比较 GMaven 和 GMavenPlus 插件之间的差异，请访问[`docs.codehaus.org/display/GMAVENPLUS/Choosing+Your+Build+Tool`](http://docs.codehaus.org/display/GMAVENPLUS/Choosing+Your+Build+Tool)。

您可以在[`groovy.github.io/GMavenPlus/index.html`](http://groovy.github.io/GMavenPlus/index.html)找到有关如何配置插件的说明。

## 准备工作

创建一个名为`ch3.building_software/running_groovy`的目录。

### 提示

**脚本的可维护性**

为了以后重复使用，请考虑在构建文件之外集中您的 Groovy 代码。

## 如何做...

1.  在模板文件（在介绍中提到）的`</project>`标签之前添加以下代码行。确保`pom.xml`文件可被 Jenkins 读取：

    ```
    <build>
      <plugins>
        <plugin>
          <groupId>org.codehaus.gmaven</groupId>
          <artifactId>gmaven-plugin</artifactId>
          <version>1.3</version>
          <executions><execution>
          <id>run-myGroovy</id>
          <goals><goal>execute</goal></goals>
          <phase>verify</phase>
          <configuration>
            <classpath>
              <element>
                <groupId>commons-lang</groupId>
                <artifactId>commons-lang</artifactId>
                <version>2.6</version>
              </element>
            </classpath>
            <source>
              Import org.apache.commons.lang.SystemUtils
              if(!SystemUtils.IS_OS_UNIX) { fail("Sorry, Not a UNIX box")}
              def command="ls -l".execute()
              println "OS Type ${SystemUtils.OS_NAME}"
              println "Output:\n ${command.text}"
            </source>
          </configuration>
          </execution></executions>
        </plugin>
      </plugins>
    </build>
    ```

1.  创建一个自由风格的作业，将**作业名称**设为`ch3.groovy_verify`。

1.  在**源代码管理**部分，勾选**文件系统**并在**路径**字段中输入您的绘图目录的完整路径，例如`/var/lib/jenkins/cookbook/ch3.building_software/running_groovy`。

1.  在**构建**部分中，为**调用顶级 Maven 目标**选择**添加构建步骤**。在新展开的部分中，添加以下细节：

    +   **Maven 版本**：`3.2.1`

    +   **目标**：`verify`

1.  运行作业。如果您的系统是在*NIX 系统上，您将获得以下输出：

    ```
    OS Type Linux
    Output:
    total 12
    -rwxrwxrwx 1 jenkins jenkins 1165 2011-09-02 11:03 pom.xml
    drwxrwxrwx 1 jenkins jenkins 3120 2014-09-02 11:03 target

    ```

    在已正确配置 Jenkins 的 Windows 系统上，脚本将失败并显示以下消息：

    ```
    Sorry, Not a UNIX box

    ```

## 它是如何工作的...

您可以在构建过程中多次执行 GMaven 插件。在示例中，`verify`阶段是触发点。

要使 Groovy 插件能够找到其核心功能之外导入的类，您需要在`<classpath>`标签中添加一个元素。源代码包含在`<source>`标签内：

```
Import org.apache.commons.lang.SystemUtils
if(!SystemUtils.IS_OS_UNIX) { fail("Sorry, Not a UNIX box")}
def command="ls -l".execute()
println "OS Type ${SystemUtils.OS_NAME}"
println "Output:\n ${command.text}"
```

`Import`语句起作用是因为依赖项在`<classpath>`标签中被提及。

`SystemUtils`类（[`commons.apache.org/proper/commons-lang/javadocs/api-2.6/org/apache/commons/lang/SystemUtils.html`](https://commons.apache.org/proper/commons-lang/javadocs/api-2.6/org/apache/commons/lang/SystemUtils.html)）提供助手方法，例如判断您正在运行哪个操作系统、Java 版本和用户的主目录。

在这种情况下，`fail`方法允许 Groovy 脚本使构建失败，注意当您不在*NIX 操作系统上运行构建时。大部分时间，您希望您的构建是与操作系统无关的。然而，在集成测试期间，您可能希望使用特定操作系统通过一个特定的 Web 浏览器执行功能测试。如果您的测试发现自己在错误的节点上，检查将停止构建。

### 提示

一旦您满意您的 Groovy 代码，请考虑将代码编译成底层 Java 字节码。您可以在 [`docs.codehaus.org/display/GMAVEN/Building+Groovy+Projects`](http://docs.codehaus.org/display/GMAVEN/Building+Groovy+Projects) 找到完整的说明。

## 还有更多...

以下是您可能会发现有用的一些提示。

### 警告跟踪

重要的是要审查您的日志文件，不仅在失败时，还要注意警告。在这种情况下，您会看到两个警告：

+   `[WARNING] 使用平台编码（实际上是 UTF-8）进行复制`

+   `[WARNING] JAR will be empty - no content was marked for inclusion!`

平台编码警告说明将使用默认平台编码复制文件。如果更改服务器并且服务器上的默认编码不同，则复制结果也可能不同。为了保持一致性，最好在`<build>`标签之前添加以下行以强制在文件中使用特定编码：

```
<properties><project.build.sourceEncoding>UTF8</project.build.sourceEncoding>
</properties>
```

更新您的模板文件以考虑这一点。

JAR 警告是因为我们只运行了一个脚本，并没有内容来制作一个 JAR。如果您在比 JAR 打包更早的阶段调用了脚本，就不会触发警告。

### 我的源代码在哪里？

还有两种指向要执行的 Groovy 脚本的方法。第一种方法是指向文件系统，如下所示：

```
<source>${script.dir}/scripts/do_some_good.Groovy</source>
```

另一种方法是通过以下方式通过 URL 连接到 Web 服务器：

```
<source>http://localhost/scripts/test.Groovy</source>
```

使用 Web 服务器存储 Groovy 脚本会为基础架构增加额外的依赖性。但是，它也非常适合在具有 Web 访问权限的 SCM 中集中代码。

### Maven 阶段

Jenkins 将工作组合在作业中。它对于具有预先和后续构建支持的粗粒度构建是有效的。相比之下，Maven 更加精细，具有 21 个阶段作为触发点。有关更多信息，请访问 [`Maven.apache.org/guides/introduction/introduction-to-the-lifecycle.html`](http://Maven.apache.org/guides/introduction/introduction-to-the-lifecycle.html)。

目标绑定阶段。例如，有四个阶段 `pre-site`、`site`、`post-site` 和 `site-deploy` 用于站点目标，所有这些阶段都将按顺序由 `mvn site` 调用，或者直接使用 `mvn site:phase` 语法调用。

思想是将一系列轻量级作业串在一起。您应该将任何重型作业（例如集成测试或大量 JavaDoc 生成）分配给从节点。您还应该按时间分离以均匀负载并帮助诊断问题。

您可以在 [`git-wip-us.apache.org/repos/asf?p=maven.git;a=blob;f=maven-core/src/main/resources/META-INF/plexus/components.xml`](https://git-wip-us.apache.org/repos/asf?p=maven.git;a=blob;f=maven-core/src/main/resources/META-INF/plexus/components.xml) 找到 XML 配置生命周期代码的方式。

您会在 `components.xml` 中的以下行下找到 Maven 阶段的提及：

```
<!-- START SNIPPET: lifecycle -->
```

Maven 插件绑定到特定阶段。对于站点生成，`<reporting>` 标签围绕大部分配置。在报告下配置的插件生成有用信息，其结果保存在 `target/site` 目录下。有一些插件会获取生成的结果，然后绘制它们的历史。一般来说，Jenkins 插件不执行测试；它们消耗结果。有一些例外，比如 Sloccount 插件 ([`wiki.jenkins-ci.org/display/JENKINS/SLOCCount+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/SLOCCount+Plugin)) 和任务扫描器插件 ([`wiki.jenkins-ci.org/display/JENKINS/Task+Scanner+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Task+Scanner+Plugin))。这些差异将在稍后的 第五章 *使用度量改进质量* 中探讨。

### 注意

要安装 sloccount 插件，您首先需要安装静态分析实用程序插件。

Groovy 插件在所有阶段都非常有用，因为它不专门针对任何特定任务，比如打包或部署。它为您提供了一种统一的方法来应对超出 Maven 通用功能范围之外的情况。

### 小贴士

**Maven 版本之间的差异**

要升级到 Maven 3 项目之间的 Maven 2 和 Maven 3，您需要了解差异和不兼容性。有一些差异，特别是围绕站点生成。它们在 [`cwiki.apache.org/confluence/display/MAVEN/Maven+3.x+Compatibility+Notes`](https://cwiki.apache.org/confluence/display/MAVEN/Maven+3.x+Compatibility+Notes) 中总结。

您可以在 [`cwiki.apache.org/confluence/display/MAVEN/Maven+3.x+Plugin+Compatibility+Matrix`](https://cwiki.apache.org/confluence/display/MAVEN/Maven+3.x+Plugin+Compatibility+Matrix) 找到插件兼容性列表。

## 另请参阅

+   在 Maven 中通过 Groovy 运行 Ant 的配方

+   使用 groovy-postbuild 插件 *响应生成的数据的差异* 配方

+   *自适应站点生成* 配方

# 操作环境变量

本配方向您展示如何将变量从 Jenkins 传递到您的构建作业，并说明不同变量是如何被覆盖的。它还描述了一种在关键信息未正确传递时使构建失败的方法。

在典型的开发/验收/生产环境中，您可能希望保留相同的 `pom.xml` 文件，但传递不同的配置。一个示例是属性文件的扩展名，例如 `.dev`、`.acc` 和 `.prd`。如果由于人为错误导致关键配置值丢失，您将希望使构建失败。

Jenkins 有许多插件可用于将信息传递给构建，包括 EnvFile 插件 ([`wiki.jenkins-ci.org/display/JENKINS/Envfile+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Envfile+Plugin)) 和 EnvInject 插件 ([`wiki.jenkins-ci.org/display/JENKINS/EnvInject+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/EnvInject+Plugin))。由于 EnvInject 插件据说可以与节点一起工作并提供广泛的属性注入选项，因此选择了 EnvInject 插件用于此配方。

## 准备工作

安装 EnvInject 插件 ([`wiki.jenkins-ci.org/display/JENKINS/EnvInject+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/EnvInject+Plugin))。创建名为`ch3.building_software/environment`的配方目录。

## 如何操作...

1.  创建一个可由 Jenkins 读取的`pom.xml`文件，并添加以下代码行：

    ```
    <project 

    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>org.berg</groupId>
    <artifactId>ch3.jenkins.builds.properties</artifactId>
    <version>1.0-SNAPSHOT</version>
    <name>${name.from.jenkins}</name>
    <properties><project.build.sourceEncoding>UTF8</project.build.sourceEncoding>
    </properties>
    <build>
    <plugins><plugin>
    <groupId>org.codehaus.gmaven</groupId>
    <artifactId>gmaven-plugin</artifactId>
    <version>1.3</version>
    <executions><execution>
    <id>run-myGroovy</id>
    <goals><goal>execute</goal></goals>
    <phase>verify</phase>
    <configuration>
    <source>
    def environment = System.getenv()
    println "----Environment"
    environment.each{println it } 
    println "----Property"
    println(System.getProperty("longname"))
    println "----Project and session"
    println "Project: ${project.class}"
    println "Session: ${session.class}"
    println "longname: ${project.properties.longname}"
    println "Project name: ${project.name}"
    println "JENKINS_HOME: ${project.properties.JENKINS_HOME}"
    </source>
    </configuration>
    </execution></executions>
    </plugin></plugins>
    </build>
    </project>
    ```

1.  在与`pom.xml`文件相同的目录中创建一个名为`my.properties`的文件。然后，在`my.properties`文件中添加以下代码行：

    ```
    project.type=prod
    secrets.file=/etc/secrets
    enable.email=true
    JOB_URL=I AM REALLY NOT WHAT I SEEM
    ```

1.  创建一个空白的自由风格作业，**作业名称**为`ch3.environment`。

1.  在**源码管理**部分，勾选**文件系统**并在**路径**字段中添加您目录的完全合格路径，例如`/var/lib/jenkins/cookbook/ch3.building_software/environment`。

1.  在**构建**部分，为**调用顶级 Maven 目标**选择**添加一个构建步骤**。在新展开的部分中，添加以下细节：

    +   **Maven 版本**: `3.2.1`

    +   **目标**: `verify`

1.  点击**高级**按钮，在**属性**中键入`longname=超级好`。

1.  通过选中作业配置页面顶部附近的**为作业准备环境**复选框来注入`my.properties`中的值。

1.  对于**属性文件路径**，添加`/full_path/my.properties`；例如`/home/var/lib/cookbook/ch3.building_software/environment/my.properties`。

    前面的选项如下图所示：

    ![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_05.jpg)

1.  运行作业。构建将失败:

    ```
    ----Project and session
    Project: class org.apache.Maven.model.Model
    Session: class org.apache.Maven.execution.MavenSession
    longname: SuperGood
    [INFO] -------------------------------------------------------
    [ERROR] BUILD ERROR
    [INFO] -------------------------------------------------------
    [INFO] Groovy.lang.MissingPropertyException: No such property: name for class: script1315151939046

    ```

1.  在**构建**部分，对于**调用顶级 Maven 目标**，点击**高级**按钮。在新展开的部分中，添加一个额外的属性 `name.from.jenkins=带名称的构建`。

1.  运行作业。现在应该成功了。

## 工作原理...

EnvInject 插件对于将属性注入到构建中非常有用。

在这个配方中，Maven 被运行了两次。第一次，它在没有定义`name.from.jenkins`变量的情况下运行，Jenkins 作业失败了。第二次，它在定义了该变量的情况下运行，Jenkins 作业现在成功了。

Maven 期望定义了`name.from.jenkins`变量，否则项目的名称也将不会被定义。通常，这还不足以阻止您的作业成功。但是，当运行 Groovy 代码时，特别是`println "Project name: ${project.name}"`行中的`project.name`调用将导致构建失败。这对于防止缺少属性值非常有用。

Groovy 代码可以看到`org.apache.Maven.model.Model`项目的实例和`org.apache.Maven.execution.MavenSession`类的实例。项目实例是您可以以编程方式访问的 XML 配置的模型。您可以通过`project.properties.longname`引用来获取`longname`属性。如果属性不存在，您的 Maven 目标将失败。您还可以通过`System.getProperty("longname")`调用获取属性。但是，您无法通过使用`System.getenv()`环境调用获取属性。

值得学习各种选项：

+   **保留 Jenkins 环境变量** 和 **保留 Jenkins 构建变量**：这两个选项影响您的作业看到的与 Jenkins 相关的变量。保持您的环境尽可能干净是很好的，因为这将有助于您以后进行调试。

+   **属性内容**：您可以覆盖属性文件中的特定值。

+   **环境脚本文件路径**：此选项指向一个脚本，该脚本将设置您的环境。如果您想要检测运行环境的特定细节并相应地配置构建，这将非常有用。

+   **填充构建原因**：您可以使 Jenkins 设置`BUILD_CAUSE`环境变量。该变量包含有关触发作业的事件的信息。

## 还有更多...

Maven 有一个用于读取属性的插件（[`mojo.codehaus.org/properties-maven-plugin/`](http://mojo.codehaus.org/properties-maven-plugin/)）。要在属性文件之间进行选择，您需要在插件配置中设置一个变量，并在 Jenkins 作业中调用它，如下所示：

```
<build>
<plugins>
<plugin>
<groupId>org.codehaus.mojo</groupId>
<artifactId>properties-maven-plugin</artifactId>
<version>1.0-alpha-2</version>
<executions>
<execution>
<phase>initialize</phase>
<goals>
<goal>read-project-properties</goal>
</goals>
<configuration>
<files>
<file>${fullpath.to.properties}</file>
</files>
</configuration>
</execution>
</executions>
</plugin>
</plugins>
</build>
```

如果您使用相对路径到属性文件，则该文件可以驻留在您的源代码中。如果您使用全路径，则属性文件可以存储在 Jenkins 服务器上。如果包含敏感密码（例如数据库连接密码），则第二个选项更可取。

Jenkins 有能力在您手动运行作业时请求变量。这称为参数化构建（[`wiki.jenkins-ci.org/display/JENKINS/Parameterized+Build`](https://wiki.jenkins-ci.org/display/JENKINS/Parameterized+Build)）。在构建时，您可以通过从属性文件位置的选择中进行选择来选择您的属性文件。

## 另请参见

+   *在 Maven 中通过 Groovy 运行 Ant* 的步骤

# 在 Maven 中通过 Groovy 运行 Ant

Jenkins 与技术背景广泛的观众进行交互。有许多开发人员在转向使用 Maven 之前已经熟练掌握了 Ant 脚本编写，这些开发人员可能更喜欢编写 Ant 任务而不是编辑`pom.xml`文件。在大部分组织中，仍然运行着关键任务的 Ant 脚本。

在 Maven 中，您可以直接使用 AntRun 插件（[`maven.apache.org/plugins/maven-antrun-plugin/`](http://maven.apache.org/plugins/maven-antrun-plugin/)）或通过 Groovy（[`docs.codehaus.org/display/GROOVY/Using+Ant+from+Groovy`](http://docs.codehaus.org/display/GROOVY/Using+Ant+from+Groovy)）运行 Ant 任务。AntRun 代表了一条自然的迁移路径。这是最初工作量最小的路径。

对于将 Groovy 作为任务的一部分使用的 Jenkins 管理员来说，Groovy 方法是有意义的。Groovy 作为一种一流的编程语言，拥有一系列难以在 Ant 中复制的控制结构。您可以部分地通过使用`Ant-contrib`库（[`ant-contrib.sourceforge.net`](http://ant-contrib.sourceforge.net)）来实现这一点。然而，作为一个功能丰富的编程语言，Groovy 更加表达力强。

本教程详细介绍了如何运行涉及 Groovy 和 Ant 的两个 Maven POM。第一个 POM 向您展示了如何在 Groovy 中运行最简单的 Ant 任务，而第二个则执行一个 Ant-contrib 任务，以安全地从大量计算机复制文件。

## 准备工作

创建一个名为`ch3.building_software/antbuilder`的目录。

## 如何做...

1.  创建一个模板文件并命名为`pom_ant_simple.xml`。

1.  更改`groupId`、`artifactId`、`version`和`name`的值以适应您的偏好。

1.  在`</project>`标签之前添加以下 XML 片段：

    ```
    <build>
    <plugins><plugin>
    <groupId>org.codehaus.gmaven</groupId>
    <artifactId>gmaven-plugin</artifactId>
    <version>1.3</version>
    <executions>
    <execution>
    <id>run-myGroovy-test</id>
    <goals><goal>execute</goal></goals>
    <phase>test</phase>
    <configuration>
    <source>
    def ant = new AntBuilder()
    ant.echo("\n\nTested ----> With Groovy")
    </source>
    </configuration>
    </execution>
    <execution>
    <id>run-myGroovy-verify</id>
    <goals><goal>execute</goal></goals>
    <phase>verify</phase>
    <configuration>
    <source>
    def ant = new AntBuilder()
    ant.echo("\n\nVerified at ${new Date()}")
    </source>
    </configuration>
    </execution>
    </executions>
    </plugin></plugins>
    </build>
    ```

1.  运行`mvn test –f pom_ant_simple.xml`。查看输出（请注意，没有关于空 JAR 文件的警告）：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_06.jpg)

1.  运行`mvn verify –f pom_ant_simple.xml`。查看输出；它应该类似于以下屏幕截图：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_07.jpg)

1.  创建第二个模板文件并命名为`pom_ant_contrib.xml`。

1.  更改`groupId`、`artifactId`、`version`和`name`的值以适应您的偏好。

1.  在`</project>`标签之前添加以下 XML 片段：

    ```
    <build>
    <plugins><plugin>
    <groupId>org.codehaus.gmaven</groupId>
    <artifactId>gmaven-plugin</artifactId>
    <version>1.3</version>
    <executions><execution>
    <id>run-myGroovy</id>
    <goals><goal>execute</goal></goals>
    <phase>verify</phase>
    <configuration>
    <source>
    def ant = new AntBuilder()
    host="Myhost_series"
    print "user: "
    user = new String(System.console().readPassword())
    print "password: "
    pw = new String(System.console().readPassword())

    for ( i in 1..920) {
    counterStr=String.format('%02d',i)
    ant.scp(trust:'true',file:"${user}:${pw}${host}${counterStr}:/${full_path_to_location}",
    localTofile:"${myfile}-${counterStr}", verbose:"true")   
    }
    </source>
    </configuration>
    </execution></executions>
    <dependencies>
    <dependency>
    <groupId>ant</groupId>
    <artifactId>ant</artifactId>
    <version>1.6.5</version>
    </dependency>
    <dependency>
    <groupId>ant</groupId>
    <artifactId>ant-launcher</artifactId>
    <version>1.6.5</version>
    </dependency>
    <dependency>
    <groupId>ant</groupId>
    <artifactId>ant-jsch</artifactId>
    <version>1.6.5</version>
    </dependency>
    <dependency>
    <groupId>com.jcraft</groupId>
    <artifactId>jsch</artifactId>
    <version>0.1.42</version>
    </dependency>
    </dependencies>
    </plugin></plugins>
    </build>
    ```

这只是代表性代码，除非您已经设置它指向真实服务器上的真实文件：

```
mvn verify –f pom_ant_simple.xml will fail

```

## 它的工作原理...

Groovy 运行基本的 Ant 任务而无需额外的依赖关系。创建一个`AntBuilder`实例（[`groovy.codehaus.org/Using+Ant+Libraries+with+AntBuilder`](http://groovy.codehaus.org/Using+Ant+Libraries+with+AntBuilder)），然后调用 Ant echo 任务。在底层，Groovy 调用 Ant 用于执行`echo`命令的 Java 类。在`echo`命令中，通过直接创建一个匿名对象打印日期：

```
ant.echo("\n\nVerified at ${new Date()}").
```

您配置了`pom.xml`文件以在两个阶段触发 Groovy 脚本：`test`阶段，然后稍后在`verify`阶段。`test`阶段发生在生成 JAR 文件之前，因此避免了创建有关空 JAR 文件的警告。顾名思义，此阶段用于打包前的测试。

第二个示例脚本突显了将 Groovy 与 Ant 结合使用的优势。SCP 任务 ([`ant.apache.org/manual/Tasks/scp.html`](http://ant.apache.org/manual/Tasks/scp.html)) 在许多服务器上多次运行。脚本首先要求输入用户名和密码，避免存储在您的文件系统或版本控制系统中。Groovy 脚本期望您注入 `host`、`full_path_to_location` 和 `myfile` 变量。

注意 Ant SCP 任务与 `pom_ant_contrib.xml` 文件中表达方式的相似之处。

## 还有更多...

通过 Groovy 运行 Ant 的另一个示例是动态创建自定义属性文件。这允许您将信息从一个 Jenkins 作业传递到另一个作业。

您可以通过 AntBuilder 使用 `echo` 任务创建属性文件。以下代码行创建一个包含两行 `x=1` 和 `y=2` 的 `value.properties` 文件：

```
def ant = new AntBuilder()
ant.echo(message: "x=1\n", append: "false", file: "values.properties")
ant.echo(message: "y=2\n", append: "true", file: "values.properties")
```

第一个 `echo` 命令将 `append` 设置为 `false`，这样每次构建发生时，都会创建一个新的属性文件。第二个 `echo` 附加其消息。

### 注意

你可以移除第二个 `append` 属性，因为默认值已设置为 `true`。

## 另请参阅

+   *通过 Maven 运行 Groovy 脚本* 配方

# 基于 JSP 语法错误导致 Jenkins 作业失败

**JavaServer Pages** (**JSP**) ([`www.oracle.com/technetwork/java/overview-138580.html`](http://www.oracle.com/technetwork/java/overview-138580.html)) 是一种使创建简单 Web 应用程序变得简单的标准。您可以将 HTML 编写到文本文件中，例如带有额外标签的页面与 Java 代码交错。如果您在运行的 Web 应用程序中执行此操作，则代码将在下一页调用时重新编译。此过程支持敏捷编程实践，但风险在于开发人员编写混乱、难以阅读的 JSP 代码，难以维护。如果 Jenkins 能够显示有关代码质量的指标，那将很好。

用户首次请求页面时，JSP 页面会即时编译。用户会将此视为页面加载缓慢，并可能阻止他们未来的访问。为了避免这种情况，您可以在构建过程中编译 JSP 页面，并将编译后的代码放置在您 Web 应用程序的 `WEB-INF/classes` 目录中或打包到 `WEB-INF/lib` 目录中。这种方法具有更快的第一页加载速度的优势。

拥有已编译源代码的次要优势是您可以在代码库上运行许多统计代码审查工具，并获取可测试性指标。这将生成供 Jenkins 插件显示的测试数据。

本文介绍了如何基于 maven-jetty-jspc-plugin ([`www.eclipse.org/jetty/documentation/current/jetty-jspc-maven-plugin.html`](http://www.eclipse.org/jetty/documentation/current/jetty-jspc-maven-plugin.html)) 编译 JSP 页面的配方。编译后的代码将与 Jetty 服务器一起使用，Jetty 服务器通常用于集成测试。

### 注意

本教程中提到的 JSP 故意不安全，因此稍后在本书中进行测试。

用于 Tomcat 部署的补充插件是 Tomcat Maven 插件 ([`tomcat.apache.org/maven-plugin.html`](http://tomcat.apache.org/maven-plugin.html))。

## 准备工作

创建一个名为 `ch3.building_software/jsp_example` 的目录。

## 如何操作...

1.  通过输入以下命令从 Maven 原型创建一个 WAR 项目：

    ```
    mvn archetype:generate -DarchetypeArtifactId=maven-archetype-webapp

    ```

1.  输入以下值：

    +   **groupId**: `ch3.packt.builds`

    +   **artifactId**: `jsp_example`

    +   **version**: `1.0-SNAPSHOT`

    +   **package**: `ch3.packt.builds`

1.  单击 **输入以确认值**。

1.  通过添加以下构建部分编辑 `jsp_example/pom.xml` 文件：

    ```
    <build>
    <finalName>jsp_example</finalName>
    <plugins>
    <plugin>
    <groupId>org.mortbay.jetty</groupId>
    <artifactId>maven-jetty-jspc-plugin</artifactId>
    <version>6.1.14</version>
    <executions>
    <execution>
    <id>jspc</id>
    <goals>
    <goal>jspc</goal>
    </goals>
    <configuration>
    </configuration>
    </execution>
    </executions>
    </plugin>
    <plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-war-plugin</artifactId>
    <version>2.4</version>
    <configuration>
    <webXml>${basedir}/target/web.xml</webXml>
    </configuration>
    </plugin>
    </plugins>
    </build>
    ```

1.  将 `src/main/webapp/index.jsp` 文件中的代码段替换为以下代码行：

    ```
    <html>
      <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Hello World Example</title>
      </head>
      <body>
        <% String evilInput= null;
          evilInput = request.getParameter("someUnfilteredInput");
          if (evilInput==null){evilInput="Hello Kind Person";}
        %>
        <form action="index.jsp">
          The big head says: <%=evilInput%><p>
          Please add input:<input type='text' name='someUnfilteredInput'>
          <input type="submit">
        </form>
      </body>
    </html>
    ```

1.  使用 `mvn package` 命令创建 WAR 文件。

1.  修改 `./src/main/webapp/index.jsp`，在以 `if` 开头的行下面添加 `if (evilInput==null)`，以使其不再是有效的 JSP 文件。

1.  运行 `mvn package` 命令。现在，构建将因以下错误消息而失败：

    ```
    [ERROR] Failed to execute goal org.mortbay.jetty:maven-jetty-jspc-plugin:6.1.14:jspc (jspc) on project jsp_example: Failure processing jsps -> [Help 1]

    ```

## 工作原理...

您使用原型创建了一个模板项目。

Maven 插件在看到 `index.jsp` 页面时，会将其编译为名为 `jsp.index_jsp` 的类，并将编译后的类放置在 `WEB-INF/classes` 下。然后，该插件在 `WEB-INF/web.xml` 中将该类定义为一个 servlet，并将其映射到 `/index.jsp`。让我们看一下以下示例：

```
<servlet>
  <servlet-name>jsp.index_jsp</servlet-name>
  <servlet-class>jsp.index_jsp</servlet-class>
</servlet>

<servlet-mapping>
  <servlet-name>jsp.index_jsp</servlet-name>
  <url-pattern>/index.jsp</url-pattern>
</servlet-mapping>
```

### 提示

原型列表会随着时间的推移而增加。您可以在 [`maven-repository.com/archetypes`](http://maven-repository.com/archetypes) 找到完整的列表。如果您正在使用 Ubuntu，则会在 `~/.m2` 目录中找到名为 `archetype-catalog.xml` 的本地 XML 目录，其中列出了所有的原型。

## 还有更多...

以下是您应考虑的一些事项。

### 不同的服务器类型

默认情况下，Jetty Maven 插件（版本 6.1.14）使用 JDK 15 加载 JSP 2.1 库。这对于所有服务器类型都不起作用。例如，如果将此教程生成的 WAR 文件部署到 Tomcat 7 服务器上，则将无法正确部署。如果查看 `logs/catalina.out`，您将看到以下错误：

```
javax.servlet.ServletException: Error instantiating servlet class jsp.index_jsp
Root Cause
java.lang.NoClassDefFoundError: Lorg/apache/jasper/runtime/ResourceInjector;

```

这是因为不同的服务器对 JSP 代码的编译方式以及运行所依赖的库有不同的假设。对于 Tomcat，您需要调整所使用的编译器以及 Maven 插件的依赖关系。有关更多详细信息，请访问 [`wiki.eclipse.org/Jetty/Feature/Jetty_Maven_Plugin`](http://wiki.eclipse.org/Jetty/Feature/Jetty_Maven_Plugin)。

### Eclipse JSP 页面模板

Eclipse 是 Java 开发人员的流行开源 IDE ([`www.eclipse.org/`](http://www.eclipse.org/))。如果您正在使用 Eclipse 的默认 JSP 页面模板，则您的页面可能无法编译。这是因为在撰写本文时，默认编译器不喜欢在 `<html>` 标签之前提及的元信息，如下所示：

```
<%@ page language="java" contentType="text/html;charset=UTF-8"
pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
```

由于元信息遵循 JSP 规范，所以很可能以后 JSP 编译器会接受这些信息。在那一天之前，只需在编译之前删除这些行或更改你使用的 JSP 编译器。

## 另请参阅

+   *配置 Jetty 进行集成测试*配方

# 配置 Jetty 进行集成测试

通常保留测试历史记录的 Jenkins 插件是 Maven 构建中生成的数据的使用者。要让 Maven 自动运行集成、性能或功能测试，它需要访问一个活动的测试服务器。你有两个主要选择：

+   **部署你的艺术品，比如 WAR 文件到一个活动的服务器**：这可以通过 Maven Wagon 插件（[`mojo.codehaus.org/wagon-maven-plugin/`](http://mojo.codehaus.org/wagon-maven-plugin/)）或通过一个 Jenkins 插件来完成，比如名为 Deploy 的插件（[`wiki.jenkins-ci.org/display/JENKINS/Deploy+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Deploy+Plugin)）。

+   **在构建中运行轻量级 Jetty 服务器**：这简化了你的基础设施。但是，服务器将作为 Jenkins 作业的一部分运行，消耗潜在的稀缺资源。这将限制 Jenkins 可以运行的并行执行器数量，降低作业的最大吞吐量。这应该委托给专门为此目的设置的专用从节点。

这个配方运行了在*基于 JSP 语法错误的失败 Jenkins 作业*配方中开发的 Web 应用程序，通过在运行测试之前启动服务器并在测试之后关闭来将 Jetty 与集成测试联系起来。该构建创建了一个自签名证书。为 HTTP 和安全的 TLS 流量定义了两个 Jetty 连接器。为了创建一个到 Telnet 的端口，还定义了`shutdown`命令。

## 准备工作

按照*基于 JSP 语法错误的失败 Jenkins 作业*配方生成一个 WAR 文件。将项目复制到名为`ch3.building_software/jsp_jetty`的目录中。

## 如何做...

1.  在`pom.xml`文件的`</plugins>`标签之前添加以下 XML 片段：

    ```
    <plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>keytool-maven-plugin</artifactId>
    <version>1.5</version>
    <executions>
    <execution>
    <phase>generate-resources</phase>
    <id>clean</id>
    <goals>
    <goal>clean</goal>
    </goals>
    </execution>
    <execution>
    <phase>generate-resources</phase>
    <id>generateKeyPair</id>
    <goals>
    <goal>generateKeyPair</goal>
    </goals>
    </execution>
    </executions>
    <configuration>
    <keystore>${project.build.directory}/jetty-ssl.keystore</keystore>
    <dname>cn=HOSTNAME</dname>
    <keypass>jetty8</keypass>
    <storepass>jetty8</storepass>
    <alias>jetty8</alias>
    <keyalg>RSA</keyalg>
    </configuration>
    </plugin>
    <plugin>
    <groupId>org.mortbay.jetty</groupId>
    <artifactId>jetty-maven-plugin</artifactId>
    <version>8.1.16.v20140903</version>
    <configuration>
    <war>${basedir}/target/jsp_example.war</war>
    <stopPort>8083</stopPort>
    <stopKey>stopmeplease</stopKey>
    <connectors>
    <connector implementation="org.eclipse.jetty.server.nio.SelectChannelConnector">
    <port>8082</port>
    </connector>
    <connector implementation="org.eclipse.jetty.server.ssl.SslSocketConnector">
    <port>9443</port>
    <keystore>
    ${project.build.directory}/jetty-ssl.keystore</keystore>
    <password>jetty8</password>
    <keyPassword>jetty8</keyPassword>
    </connector>
    </connectors>
    </configuration>
    <executions>
    <execution>
    <id>start-jetty</id>
    <phase>pre-integration-test</phase>
    <goals>
    <goal>run</goal>
    </goals>
    <configuration>
    <daemon>true</daemon>
    </configuration>
    </execution>
    <execution>
    <id>stop-jetty</id>
    <phase>post-integration-test</phase>
    <goals>
    <goal>stop</goal>
    </goals>
    </execution>
    </executions>
    </plugin>
    ```

1.  运行`mvn jetty:run`命令。现在你会看到 Jetty 服务器启动时的控制台输出。

1.  使用 Web 浏览器，访问`https://localhost:9443`位置。在通过有关自签名证书的警告后，你将看到 Web 应用程序正常工作。

1.  按下*Ctrl* + *C*停止服务器。

1.  运行`mvn verify`。现在你会看到服务器启动然后停止。

## 工作原理...

在 `<executions>` 标签内，Jetty 在 Maven 的 `pre-integration-test` 阶段运行，并且在 Maven 的 `post-integration-test` 阶段停止。在 `generate-resources` 阶段，Maven 使用 `keytool` 插件创建自签名证书。证书存储在具有已知密码和别名的 Java `keystore` 中。密钥加密设置为 RSA。如果您的证书中未正确设置 **Common Name** (**CN**)，则您的网络浏览器将会报错。要将证书的 **Distinguished Name** (**DN**) 更改为您主机的名称，请修改 `<dname>cn=HOSTNAME</dname>`。

Jetty 配置有两种连接器类型：端口 `8082` 用于 HTTP，端口 `9443` 用于安全连接。选择这些端口是因为它们在端口 `1023` 以上，因此您无需管理员权限即可运行构建。端口号还避免了 Jenkins 使用的端口。`jetty` 和 `Keytool` 插件都使用 `keystore` 标签来定义密钥库的位置。

生成的 WAR 文件由 `webapp` 标签指向，并且 Jetty 运行应用程序。

### 注意

对于功能测试人员来说，使用自签名证书会增加额外的工作量。每当他们遇到证书的新版本时，他们都需要在其网络浏览器中将证书接受为安全异常。最好使用来自知名权威机构的证书。通过删除密钥生成并将 `keystore` 标签指向已知文件位置，您可以通过此方法实现这一点。

## 还有更多...

Maven 3 对于定义插件版本比 Maven 2.2.1 更挑剔。这是有充分理由的。如果你知道你的构建能够很好地与特定版本的 Maven 配合工作，那么这可以防止不必要的变化。例如，在撰写本书时，此示例中使用的 Jetty 插件被保持在版本 8.1.16.v20140903。正如你可以从[这里的错误报告](http://jira.codehaus.org/browse/JETTY-1071)中看到的，配置细节随着版本的变化而变化。

另一个优点是，如果插件版本过旧，则插件将被从中央插件仓库中移除。当您下次清理本地仓库时，这将破坏您的构建。这正是您想要的，因为这清晰地表明了需要进行审查然后升级。

## 另请参阅

+   *基于 JSP 语法错误的 Jenkins 作业失败* 方法

+   *自适应站点生成* 方法

# 使用 Rat 查看许可证违规行为

此方法描述了如何在 Jenkins 中搜索任何作业的许可证违规情况。它基于 Apache Rat 项目 ([`creadur.apache.org/rat/`](http://creadur.apache.org/rat/))。您可以通过直接运行贡献的 Ant 任务或通过 Maven 来运行 Rat JAR 文件以搜索许可证违规情况。在此方法中，您将通过 JAR 文件直接运行。报告输出会发送到控制台，准备供 Jenkins 插件（如日志解析插件）处理信息。

## 准备工作

在 Jenkins 主目录 (`/var/lib/jenkins`) 下创建 `License_Check` 目录。登录 Jenkins。

## 怎么做...

1.  创建一个名为 `License_Check` 的 Maven 作业。

1.  在**源代码管理**部分，勾选**Subversion**。

1.  在**Modules, Repository URL**中填入 `http://svn.apache.org/repos/asf/creadur/rat/trunk/`。

1.  将**Check-out Strategy**设置为**尽可能使用 'svn update'**。

1.  在**Build**部分，添加 `clean package` 到 **Goals and options**。

1.  在**Post steps**部分，勾选**仅在构建成功时运行**。

1.  添加**Post-build step**来执行**Shell**（假设你正在运行一个 NIX 系统）。如果需要，将以下文本添加到**执行 Shell**文本区域中，替换 JAR 版本号：

    ```
    java -jar ./apache-rat/target/apache-rat-0.12-SNAPSHOT.jar --help
    java -jar ./apache-rat/target/apache-rat-0.12-SNAPSHOT.jar -d ${JENKINS_HOME}/workspace/License_Check/  -e '*.js'  -e '*target*'

    ```

1.  点击**保存**按钮并运行作业。

1.  查看作业工作区的路径。访问**配置 Jenkins**界面，例如 `http://localhost:8080/configure`。在**Home Directory**下方，点击**高级**按钮。如下截图所示，**Workspace Root Directory** 的值变得可见：![怎么做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_08.jpg)

## 它是如何工作的...

Rat 源代码被编译然后运行两次——第一次打印出帮助信息，第二次检查许可证头部。

代码库正在改变；随着时间的推移，预计选项的数量会增加。通过运行 `help`，你将找到最新的信息。

`–d` 选项告诉应用程序你的源代码在哪个目录中。在这个示例中，你使用了 `${JENKINS_HOME}` 变量来定义路径的顶层。接下来，我们假设作业位于 `./job/jobname/workspace` 目录下。你在第 9 步骤中检查了这个假设是否正确。如果不正确，你需要调整选项。要为另一个项目生成报告，只需通过替换作业名称更改路径。

`–e` 选项排除了某些文件名模式的审核。你已经排除了 JavaScript 文件 `'*.js'` 和 `'*target*'`，适用于目标目录下的所有生成文件。在一个复杂的项目中，预计会有很长的排除列表。

### 注意

即使要检查的目录不存在，构建仍将成功，并报告错误如下：

```
ERROR: /var/lib/jenkins/jobs/License_Check/workspace
Finished: Success

```

你将需要使用一个日志解析插件来强制失败

## 更多内容...

用于更新源代码许可证的一款 Maven 插件是 maven-license 插件 ([`code.mycila.com/license-maven-plugin/`](http://code.mycila.com/license-maven-plugin/))。你可以使用它来保持源代码许可头部的更新。要添加/更新源代码的 `src/etc/header.txt` 许可证，请将以下 XML 片段添加到你的构建部分：

```
<plugin>
<groupId>com.mycila.maven-license-plugin</groupId>
<artifactId>maven-license-plugin</artifactId>
<version>2.6</version>
<configuration>
<header>src/etc/header.txt</header>
</configuration>
</plugin>
```

然后你需要添加你自己的 `src/etc/header.txt` 许可证文件。

一个强大的功能是你可以添加变量来扩展。在下面的示例中，`${year}` 将会被扩展为如下内容：

```
Copyright (C) ${year} Licensed under this open source License
```

要格式化你的源代码，你需要运行以下命令：

```
mvn license:format -Dyear=2012

```

## 另请参阅

+   *在 Maven 中审查许可证违规行为*食谱

+   *使用 groovy-postbuild 插件对生成的数据进行反应*食谱

# 在 Maven 中审查许可证违规行为

在本示例中，您将通过 Maven 运行 Rat。然后它将检查源代码中的许可证违规行为。

## 准备就绪

创建名为`ch3.building_software/license_maven`的目录。

## 如何操作...

1.  创建一个模板`pom.xml`文件。

1.  更改`groupId`、`artifactId`、`version`和`name`的值以适应您的偏好。

1.  在`</project>`标记之前添加以下 XML 片段：

    ```
    <pluginRepositories>
    <pluginRepository>
    <id>apache.snapshots</id>
    <url>http://repository.apache.org/snapshots/</url>
    </pluginRepository>
    </pluginRepositories>
    <build>
    <plugins><plugin>
    <groupId>org.apache.rat</groupId>
    <artifactId>apache-rat-plugin</artifactId>
    <version>0.11-SNAPSHOT</version>
    <executions><execution>
    <phase>verify</phase>
    <goals><goal>check</goal></goals>
    </execution></executions><configuration>
    <excludeSubProjects>false</excludeSubProjects><numUnapprovedLicenses>597</numUnapprovedLicenses>
    <excludes>
    <exclude>**/.*/**</exclude>
    <exclude>**/target/**/*</exclude>
    </excludes>
    <includes>
    <include>**/src/**/*.css</include>
    <include>**/src/**/*.html</include>
    <include>**/src/**/*.java</include>
    <include>**/src/**/*.js</include>
    <include>**/src/**/*.jsp</include>
    <include>**/src/**/*.properties</include>
    <include>**/src/**/*.sh</include>
    <include>**/src/**/*.txt</include>
    <include>**/src/**/*.vm</include>
    <include>**/src/**/*.xml</include>
    </includes>
    </configuration>
    </plugin></plugins></build>
    ```

1.  使用**项目名称**为`ch3.BasicLTI_license`创建一个 Maven 项目。

1.  在**源代码管理**部分，选中**Subversion**，**URL 仓库**为`https://source.sakaiproject.org/svn/basiclti/trunk`。

    ### 注意

    不要向 SVN 仓库发送垃圾邮件。确保没有激活任何构建触发器。

1.  在**构建**部分设置，添加以下详细信息：

    +   **Root POM**：`pom.xml`

    +   **目标和选项**：`clean`

1.  在**预处理步骤**部分，调用注入环境变量并将以下内容添加到属性的上下文中：

    ```
    rat.basedir=/var/lib/Jenkins/workspace/ch3.BasicLTI_license
    ```

1.  在**后续步骤**部分，调用顶级 Maven 目标：

    +   **Maven 版本**：`3.2.1`

    +   **目标**：`verify`

1.  点击**高级**按钮。

1.  在扩展部分中，将**POM**部分设置为 Rat 的 POM 文件的完整路径，例如，`/var/lib/cookbook/ch3.building_software/license_maven/pom.xml`。

1.  在**后续步骤**部分，添加一个复制命令以将报告移动到您的工作空间（例如 `cp /var/lib/cookbook/ch3.building_software/license_maven/target/rat.txt ${WORKSPACE}`）和**执行 Shell**。

1.  运行作业。您现在可以访问工作区并查看`./target/rat.txt`。文件应类似于以下屏幕截图：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_09.jpg)

## 它是如何工作的...

您从一个开源项目中拉取了源代码；在这种情况下，从 Apereo 基金会的一个子版本和 Git 仓库中拉取（[`source.sakaiproject.org/svn/`](https://source.sakaiproject.org/svn/)）。

### 注意

2013 年，Sakai 基金会 ([www.sakaiproject.org](http://www.sakaiproject.org)) 与 JASIG ([www.jasig.org](http://www.jasig.org)) 合并成为 Apereo 基金会 ([www.apereo.org](http://www.apereo.org))。

Sakai 是被许多百万学生每天使用的**学习管理系统**（**LMS**）。Apereo 基金会代表着 100 多个组织，主要是大学。

源代码包含由 Rat Maven 插件检查的不同许可证。插件在`verify`阶段调用，并检查 Jenkins 注入的`${WORKSPACE}`变量所定义的作业的工作区位置。

将`excludeSubProjects`语句设置为`false`，告诉 Rat 除了主项目外还要访问任何子项目。`numUnapprovedLicenses`语句是在作业失败之前可接受的未批准许可证数量。

`excludes` 语句排除目标目录和任何其他目录。 `includes` 语句覆盖 `src` 目录下的特定文件类型。 根据项目中使用的框架类型，包含的范围将会改变。

### 注意

有关定制 Rat 以适用于特定许可证类型的信息，请访问：

[`creadur.apache.org/rat/apache-rat-plugin/examples/custom-license.html`](http://creadur.apache.org/rat/apache-rat-plugin/examples/custom-license.html)。

## 还有更多...

这里还有一些有用的审查提示。

### 多种方法和反模式

配置 Jenkins 作业有多种方法。 您可以通过在 Maven 插件配置中固定其位置来避免复制 Rat 报告文件。 这样做的好处是避免了复制操作。 您还可以使用多个源码管理器插件（[`wiki.jenkins-ci.org/display/JENKINS/Multiple+SCMs+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Multiple+SCMs+Plugin)）首先将源代码复制到工作空间中。 您还应考虑将其拆分为两个作业，然后将 Rat 作业指向源代码的工作空间。 最后一种方法是最佳实践，因为它清晰地将测试与源代码分开。

### 快照

与构件的固定版本不同，快照不能保证其详细信息随时间不变。 如果要测试最新和最好的内容，则快照很有用。 但是，为了获得最可维护的代码，最好使用固定版本构件。

为了捍卫基本稳定性，考虑编写一个在 `pom.xml` 文件中触发小 Groovy 脚本的作业，以访问所有项目。 脚本需要搜索 `version` 标签中的 `SNAPSHOT` 单词，然后为 groovy-postbuild 插件写入一个可识别的警告，以便该作业在必要时失败。 使用这种方法，您可以逐步加强边界，给开发人员改进其构建的时间。

## 另请参阅

+   *使用 Rat 检查许可证违规* 配方

+   *使用 groovy-postbuild 插件对生成的数据做出反应* 配方

# 通过构建描述公开信息

设置插件允许您从构建日志中获取信息，并将其作为构建历史的描述添加。 这非常有用，因为它允许您稍后快速评估问题的历史原因，而无需深入查看控制台输出。 这样可以节省很多鼠标点击。 现在，您可以立即在趋势报告中看到详细信息，而无需逐个查看所有构建结果。

设置插件使用正则表达式来解析描述。 此配方向您展示了如何做到这一点。

## 准备工作

安装描述设置插件（[`wiki.jenkins-ci.org/display/JENKINS/Description+Setter+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Description+Setter+Plugin)）。 创建一个名为 `ch3.building_software/descriptions` 的配方文件目录。

## 怎么做...

1.  创建一个模板 `pom.xml` 文件。

1.  更改`groupId`、`artifactId`、`version`和`name`的值以满足您的偏好。

1.  在`</project>`标签之前添加以下 XML 片段：

    ```
    <build>
    <plugins><plugin>
    <groupId>org.codehaus.gmaven</groupId>
    <artifactId>gmaven-plugin</artifactId>
    <version>1.3</version>
    <executions><execution>
    <id>run-myGroovy</id>
    <goals><goal>execute</goal></goals>
    <phase>verify</phase>
    <configuration>
    <source>
    if ( new Random().nextInt(50) > 25){
    fail "MySevere issue:  Due to little of resource X"
    } else {
    println "Great stuff happens because: This world is fully resourced"
    }
    </source>
    </configuration>
    </execution></executions>
    </plugin></plugins>
    </build>
    ```

1.  创建一个 Maven 项目，**作业名称**设为 `ch3.descriptions`。

1.  在**源代码管理**部分，选中**文件系统**并在**路径**字段中添加您目录的完全限定路径，例如`/var/lib/Jenkins/cookbook/ch3.building_software/description`。

1.  勾选**设置构建描述**并添加以下截图中显示的值：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_10.jpg)

1.  多次运行作业并查看**构建历史记录**。您会发现每次构建的描述都不同：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_11.jpg)

## 工作原理...

Groovy 代码是作为`install`目标的一部分调用的。该代码会根据`MySever issue`模式使作业失败，或者根据`Great stuff happens because`模式将输出打印到构建中：

```
if ( new Random().nextInt(50) > 25){
fail "MySevere issue:  Due to little of resource X"
} else {
println "Great stuff happens because: This world is fully resourced"
```

作为后置构建操作，将触发 description-setter 插件。在构建成功时，它会查找`Great stuff happens because: (.*)`模式。

`(.*)`模式将第一个模式部分后的任何文本拉入`"\1"`变量中，稍后在设置特定构建的描述中展开。

对于失败的构建也是如此，除了在`"\1"`展开之前添加了一些额外文本。您在**失败构建的描述**配置中定义了这些内容。

### 提示

可以通过扩展正则表达式获得比`\1`更多的变量。例如，如果控制台输出是`fred is happy`，那么`(.*)`模式生成的`"\1"`等于`fred`，`"\2"`等于`happy`。

## 还有更多...

该插件获取其解析文本的能力来自 token-macro 插件 ([`wiki.jenkins-ci.org/display/JENKINS/Token+Macro+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Token+Macro+Plugin))。token-macro 插件允许在文本中定义宏；然后通过调用实用方法来扩展它们。这种使用实用程序插件的方法简化了插件的创建，并支持一致性。

## 另请参阅

+   *使用 groovy-postbuild 插件响应生成的数据* 的方法

# 使用 groovy-postbuild 插件响应生成的数据

构建信息有时会被模糊地记录在日志文件或报告中，这些对于 Jenkins 来说很难暴露。本文将展示一种将这些细节拉到 Jenkins 中的方法。

groovy-postbuild 插件允许您在构建运行后运行 Groovy 脚本。因为该插件在 Jenkins 中运行，所以可以编程地访问服务，例如能够读取控制台输入或更改构建摘要页面。

该方法在 Maven 的 `pom.xml` 中使用了一个 Groovy 脚本来将文件输出到控制台。然后，插件中的 Groovy 代码会捕获控制台输入，并在构建历史记录中显示关键统计信息。构建摘要详情也被修改了。

## 准备工作

遵循*从 Maven 内部审查许可证违规*的配方。添加 groovy-postbuild 插件（[`wiki.jenkins-ci.org/display/JENKINS/Groovy+Postbuild+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Groovy+Postbuild+Plugin)）。

## 操作方法...

1.  通过在`pom.xml`文件中在`</plugins>`标记之前添加以下 XML 片段来更新文件：

    ```
    <plugin>
    <groupId>org.codehaus.gmaven</groupId>
    <artifactId>gmaven-plugin</artifactId>
    <version>1.3</version>
    <executions><execution>
    <id>run-myGroovy</id>
    <goals><goal>execute</goal></goals>
    <phase>verify</phase>
    <configuration>
    <source>
    new File("${basedir}/target/rat.txt").eachLine{line->println line}
    </source>
    </configuration>
    </execution></executions>
    </plugin>
    ```

1.  在**后构建操作**部分更新`ch3.BasicLTI_license`作业的配置。选中**Groovy Postbuild**。将以下脚本添加到 Groovy 脚本文本输入中：

    ```
    def matcher = manager.getMatcher(manager.build.logFile, "^(.*) Unknown Licenses\$")
    if(matcher?.matches()) {
    title="Unknown Licenses: ${matcher.group(1)}"
    manager.addWarningBadge(title)
    manager.addShortText(title, "grey", "white", "0px", "white")
    manager.createSummary("error.gif").appendText("<h2>${title}</h2>", false, false, false, "grey")
    manager.buildUnstable()
    }
    ```

1.  确保**如果脚本失败**选择框设置为**什么都不做**。

1.  点击**保存**。

1.  运行作业多次。在**构建历史**中，您将看到类似以下截图的结果：![操作方法...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_12.jpg)

1.  单击最新构建链接会显示有关未知许可证的摘要信息的构建页面，如以下截图所示：![操作方法...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_13.jpg)

## 它是如何工作的...

Rat 许可报告保存到`target/rat.txt`文件中。然后，Groovy 代码读取 Rat 文件并将其打印到控制台，以便 groovy-postbuild 插件接收。您可以在 groovy-postbuild 插件中完成所有工作，但以后可能希望重用构建。

构建完成后，groovy-postbuild 插件将运行。插件可见一些 Jenkins 服务：

+   `manager.build.logFile`: 这会获取日志文件，其中现在包括许可信息。

+   `manager.getMatcher`: 这会检查日志文件以查找与`"^(.*) Unknown Licenses\$"`匹配的模式。符号`^`检查行的开头，`\$`检查行的结尾。以`Unknown Licenses`模式结尾的任何行将与之前存储在`matcher.group(1)`中的任何内容匹配。它将`title`字符串设置为未知许可证的数量。

+   `manager.addWarningBadge(title)`: 这会向构建历史框添加警告徽章，`title`将用作鼠标悬停在图标上时显示的文本。

+   `manager.addShortText`: 这会在图标旁添加可见文本。

+   通过`manager.createSummary`方法创建摘要。已在 Jenkins 中存在的图像将以标题的形式添加。

## 还有更多...

通过搜索常规模式将信息提取到报告中称为爬取。爬取的稳定性依赖于在 Rat 报告中生成一致的模式。如果更改 Rat 插件的版本，则模式可能会更改并破坏报告。可能时，最好使用稳定的数据源，例如具有明确定义语法的 XML 文件。

## 另请参阅

+   *通过构建描述公开信息*配方

+   *通过小的配置更改增强安全性*配方在第二章中，*增强安全性*

# 通过 Jenkins API 远程触发作业

Jenkins 具有远程 API，允许您启用、禁用、运行和删除作业；它还允许您更改配置。API 随着每个 Jenkins 版本的增加而增加。要获取最新的详细信息，您需要查看`http://yourhost/job/Name_of_Job/api/`。其中`yourhost`是您的 Jenkins 服务器的位置，`Name_of_Job`是服务器上存在的作业的名称。

此方案详细介绍了如何使用安全令牌远程触发构建。这将允许您从 Maven 内运行其他作业。

## 准备工作

此方案期望 Jenkins 安全性已打开，以便您可以作为用户登录。它还假设您已安装了现代版本的`wget`（[`www.gnu.org/software/wget/`](http://www.gnu.org/software/wget/)）。

## 如何执行...

1.  创建一个自由风格项目，**项目名称**为`ch3.RunMe`。

1.  检查**此构建已参数化**，选择**字符串参数**，并添加以下细节：

    +   **名称**：`myvariable`

    +   **默认值**：`默认`

    +   **描述**：`这是我的示例变量`

1.  在**触发构建**部分下，勾选**远程触发构建**（例如，从脚本中）。

1.  在**身份验证令牌**文本框中添加`changeme`。

1.  点击**保存**按钮。

1.  点击**带参数构建**链接。

1.  将要求您输入名为`myvariable`的变量。点击**构建**。

1.  访问您的个人配置页面，例如`http://localhost:8080/user/your_user/configure`，其中您将`your_user`替换为您的 Jenkins 用户名。

1.  在**API 令牌**部分，点击**显示 API 令牌…**按钮。

1.  将令牌复制到`apiToken`中。

1.  从终端控制台远程运行`wget`以登录并运行作业：

    ```
    wget --auth-no-challenge --http-user=username --http-password=apiToken http://localhost:8080/job/ch3.RunMe/build?token=changeme

    ```

1.  检查 Jenkins 作业以验证其未运行并返回`405`HTTP 状态代码：

    ```
    Resolving localhost (localhost)... 127.0.0.1Connecting to localhost (localhost)|127.0.0.1|:8080... connected.
    HTTP request sent, awaiting response... 405 Method Not Allowed
    2014-08-14 15:08:43 ERROR 405: Method Not Allowed.

    ```

1.  从终端控制台运行`wget`以登录并运行返回`201`HTTP 状态代码的作业：

    ```
    wget --auth-no-challenge --http-user=username --http-password=apiToken http://localhost:8080/job/ch3.RunMe/buildWithParameters?token=changeme\&myvariable='Hello World'
    Connecting to localhost (localhost)|127.0.0.1|:8080... connected.
    HTTP request sent, awaiting response... 201 Created

    ```

    ### 注意

    HTTP 可以被第三方抓包。传输密码时请使用 HTTPS。

## 工作原理...

要运行作业，您需要作为用户进行身份验证，然后获取运行特定作业的权限。这通过`apiTokens`实现，您应该将其视为密码的一种。

有两个远程方法调用。第一个是 build，用于在不传递参数的情况下运行构建。该方法当前不被接受。第二个有效的方法是`buildWithParameters`，它期望您至少向 Jenkins 传递一个参数。参数用`\&`分隔。

`wget`工具承担了大部分工作；否则，您将不得不编写一些棘手的 Groovy 代码。为了简短的方案，我们选择了简单性和操作系统的依赖性。运行一个可执行文件会使您的构建依赖于操作系统。可执行文件将取决于底层环境的设置方式。然而，有时您需要做出妥协以避免复杂性。

有关更多详细信息，请访问 [`wiki.jenkins-ci.org/display/JENKINS/Authenticating+scripted+clients`](https://wiki.jenkins-ci.org/display/JENKINS/Authenticating+scripted+clients).

### 注意

你可以在以下网址找到等效的 Java 代码：

[`wiki.jenkins-ci.org/display/JENKINS/Remote+access+API`](https://wiki.jenkins-ci.org/display/JENKINS/Remote+access+API).

## 还有更多...

以下是一些你应该考虑的事项。

### 从 Maven 中运行作业

使用 `maven-antrun` 插件，你可以轻松运行 `wget`。以下是等效的 `pom.xml` 片段：

```
<build>
<plugin>
<groupId>org.apache.maven.plugins</groupId>
<artifactId>maven-antrun-plugin</artifactId>
<version>1.7</version>
<executions><execution>
<phase>compile</phase>
<configuration>
<tasks>
<exec executable="wget">
<arg line="--auth-no-challenge --http-user=username --http-password=apiToken http://localhost:8080/job/ch3.RunMe/build?token=changeme" />
</exec>
</tasks>
</configuration>
<goals><goal>run</goal></goals>
</execution></executions>
</plugin>
</build>
```

你可以使用 exec-maven 插件来实现与 maven-ant 插件相同的目的。有关更多详细信息，请访问 [`mojo.codehaus.org/exec-maven-plugin/`](http://mojo.codehaus.org/exec-maven-plugin/).

### 远程生成作业

还有一个项目可以让你通过 Maven 远程创建 Jenkins 作业（[`github.com/evgeny-goldin/maven-plugins/tree/master/jenkins-maven-plugin`](https://github.com/evgeny-goldin/maven-plugins/tree/master/jenkins-maven-plugin)）。这种方法的优点是它能够在作业之间强制执行一致性和重用。你可以使用一个参数选择 Jenkins 服务器并填充它。这对于生成一组结构一致的作业非常有用。

## 另请参阅

+   *在 Maven 中通过 Groovy 运行 Ant* 示例

# 自适应站点生成

Jenkins 是一个出色的通信工具。它可以消耗构建生成的测试结果。Maven 有一个用于站点生成的目标，在 `pom.xml` 文件中，许多 Maven 测试插件被配置。配置受 `reporting` 标签限制。

当站点生成时，Jenkins Maven 软件项目作业记录，并在作业主页上创建一个快捷图标。这是一个非常显眼的图标，你可以将其与内容链接起来：

![自适应站点生成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_14.jpg)

通过触发 Groovy 脚本，你可以对 Maven 站点生成进行细粒度控制，以在不同的 Maven 阶段中构建站点。

在这个示例中，你将使用 Groovy 生成一个动态站点菜单，该菜单具有根据脚本中的随机选择而不同的菜单链接。然后，第二个脚本生成每个站点生成的新结果页面。如果你想公开自定义的测试结果，这些操作非常有用。*在 Jenkins 中报告替代代码度量* 的示例描述了如何在 Jenkins 中绘制自定义结果，进一步增强用户体验。

### 注意

该示例适用于 Maven 版本 2.2.1 或更早版本。Maven 3 在站点生成方面有稍微不同的方法。

要在你的 `pom.xml` 文件中强制使用最低 Maven 版本，你需要添加 `<prerequisites><maven>2.2.1</maven></prerequisites>`。

## 准备工作

创建一个名为 `ch3.building_software/site` 的目录。安装 `Copy Data to Workspace` 插件 ([`wiki.jenkins-ci.org/display/JENKINS/Copy+Data+To+Workspace+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Copy+Data+To+Workspace+Plugin))。这将使你练习另一个有用的插件。你将使用此插件将文件复制到 Jenkins 工作空间中，如本教程中所述。这用于将包含密码的敏感配置文件复制到项目中，你不希望它们出现在版本控制系统中。

## 如何操作...

1.  在你的模板 `pom.xml` 文件中的 `</project>` 之前添加以下 XML 片段（在介绍中提到），确保 `pom.xml` 文件可被 Jenkins 读取：

    ```
    <url>My_host/my_dir</url>
    <description>This is the meaningful DESCRIPTION</description>
    <build>
    <plugins><plugin>
    <groupId>org.codehaus.gmaven</groupId>
    <artifactId>gmaven-plugin</artifactId>
    <version>1.3</version>
    <executions>
    <execution>
    <id>run-myGroovy-add-site-xml</id>
    <goals><goal>execute</goal></goals>
    <phase>pre-site</phase>
    <configuration>
    <source>
    site_xml.Groovy
    </source>
    </configuration>
    </execution>
    <execution>
    <id>run-myGroovy-add-results-to-site</id>
    <goals><goal>execute</goal></goals>
    <phase>site</phase>
    <configuration>
    <source>
    site.Groovy
    </source>
    </configuration>
    </execution></executions>
    </plugin></plugins>
    </build>
    ```

1.  在与你的 `pom.xml` 文件相同的目录中创建 `site_xml.Groovy` 文件，并使用以下代码行：

    ```
    def site= new File('./src/site')
    site.mkdirs()
    defs xml=new File('./src/site/site.xml')
    if (sxml.exists()){sxml.delete()}

    sxml<< '<?xml version="1.0" encoding="ISO-8859-1"?>'
    sxml<< '<project name="Super Project">'
    sxml<< '<body>'
    def random = new Random()
    if (random.nextInt(10) > 5){
    sxml<< '    <menu name="My super project">'
    sxml<< '     <item name="Key Performance Indicators" href="/our_results.html"/>'
    sxml<< '   </menu>'
    print "Data Found menu item created\n"
    }
    sxml<< '   <menu ref="reports" />'
    sxml<< '  </body>'
    sxml<< '</project>'

    print "FINISHED - site.xml creation\n"
    ```

1.  在与你的 `pom.xml` 文件相同的目录中添加 `site.Groovy` 文件，并使用以下代码行：

    ```
    def site= new File('./target/site')
    site.mkdirs()
    def index = new File('./target/site/our_results.html')
    if (index.exists()){index.delete()}
    index<< '<h3>ImportAnt results</h3>'
    index<< "${new Date()}\n"
    index<< '<ol>'

    def random = new Random()
    for ( i in 1..40 ) {
    index<< "<li>Result[${i}]=${random.nextInt(50)}\n"
    }
    index<< '</ol>'
    ```

1.  创建一个名为 `ch3.site` 的 Maven 项目。

1.  在 **构建** 部分，填写以下细节：

    +   **Maven 版本**: `2.2.1`

    +   **根 POM**: `pom.xml`

    +   **目标和选项**: `site`

1.  在 **构建环境** 部分，选择 **将数据复制到工作空间**。

1.  将你放置文件的任何目录（在本教程中提到）添加到 **文件夹路径** 字段。

1.  运行作业多次，查看生成的站点。在右侧，你应该看到一个名为 **我的超级项目** 的菜单部分。对于一半的运行，将会有一个名为 **关键绩效指标** 的子菜单链接：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_15.jpg)

## 工作原理...

有两个 Groovy 脚本在站点目标的两个不同阶段运行。第一个生成 `site.xml` 文件。Maven 使用此文件在索引页面的左侧创建一个额外的菜单结构。第二个 Groovy 脚本生成一个随机结果页面。

`site_xml.Groovy` 文件在 `pre-site` 阶段运行。`site.Groovy` 文件在站点生成期间执行。`site_xml.Groovy` 文件生成 `src/site` 目录，然后生成 `src/site/site.xml` 文件。这是 Maven 站点生成插件用于定义站点菜单左侧的文件。有关此过程的更多详细信息，请访问 [`Maven.apache.org/guides/mini/guide-site.html`](http://Maven.apache.org/guides/mini/guide-site.html)。

然后 Groovy 脚本在 `if (random.nextInt(10) > 5)` 行中随机决定何时显示额外的结果页面菜单项。

`site.Groovy` 文件生成一个包含 40 个条目的随机结果页面。如果存在旧的结果页面，Groovy 脚本会将其删除。该脚本通过首先创建 `target/site 目录`来稍微作弊。如果你想要更长或更短的页面，请修改 `for ( i in 1..40 ) {` 行中的数字 `40`。

构建脚本运行后，Jenkins 检查站点是否位于传统位置，并将图标添加到任务中。

### 注意

在撰写本书时，只有**Maven**项目作业意识到生成的站点的存在并发布站点图标。自由样式作业不行。

## 还有更多...

这里还有一些有用的信息。

### 搜索示例站点生成配置

有时，在配置站点生成时可能会出现任意的 XML 魔法。学习的一种快速方法是使用软件代码搜索引擎。例如，尝试使用 Black Duck 代码搜索引擎（[`code.ohloh.net/`](http://code.ohloh.net/)）搜索术语 `<reporting>`。

### Maven 2 和 3 的陷阱

Maven 3 在大多数情况下与 Maven 2 向后兼容。然而，它确实有一些你可以在[`cwiki.apache.org/confluence/display/MAVEN/Maven+3.x+Compatibility+Notes`](https://cwiki.apache.org/confluence/display/MAVEN/Maven+3.x+Compatibility+Notes)中审查的差异。关于兼容插件的列表，请访问[`cwiki.apache.org/confluence/display/MAVEN/Maven+3.x+Plugin+Compatibility+Matrix`](https://cwiki.apache.org/confluence/display/MAVEN/Maven+3.x+Plugin+Compatibility+Matrix)。

在幕后，Maven 3 是 Maven 2 的重写，具有改进的架构和性能。强调兼容性与 Maven 2。你不想破坏传统配置，因为那会导致不必要的维护工作。Maven 3 对语法比 Maven 2 更挑剔。如果你忘记为任何依赖项或插件添加版本号，它会抱怨。例如，在本书的第一版中，基于 JSP 语法错误的 *失败的 Jenkins 作业* 配方包括一个没有定义版本的 `pom.xml` 文件中的 `keytool-maven-plugin` 浮动：

```
<plugin>
<groupId>org.codehaus.mojo</groupId>
<artifactId>keytool-maven-plugin</artifactId>
<executions>
<execution>
<phase>generate-resources</phase>
<id>clean</id>
<goals>
<goal>clean</goal>
</goals>
</execution>
<execution>
<phase>generate-resources</phase>
<id>genkey</id>
<goals>
<goal>genkey</goal>
</goals>
</execution>
</executions>
```

当使用 Maven 3 运行时，该配方将失败，并显示以下输出。

![Maven 2 和 3 的陷阱](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_16.jpg)

`genkey` 目标不再存在，因为 Maven 3 正在使用最新版本的插件进行扫描，即版本 1.5。在插件的网站[`mojo.codehaus.org/keytool/keytool-maven-plugin/`](http://mojo.codehaus.org/keytool/keytool-maven-plugin/)上查看，明显我们需要更新版本号和目标：

![Maven 2 和 3 的陷阱](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_17.jpg)

更改体现在更新的 `pom.xml` 文件中：

```
<plugin>
  <groupId>org.codehaus.mojo</groupId>
  <artifactId>keytool-maven-plugin</artifactId>
 <version>1.5</version>
  <executions>
    <execution>
      <phase>generate-resources</phase>
      <id>clean</id>
      <goals>
        <goal>clean</goal>
      </goals>
    </execution>
    <execution>
      <phase>generate-resources</phase>
        <id>generateKeyPair</id>
        <goals>
 <goal>generateKeyPair</goal>
        </goals>
    </execution>
  </executions>
</plugin>
```

另一个陷阱是 Maven 3 中 Maven 站点插件的使用反映在 `<reporting>` 部分配置的方式上。

从 Maven 2 升级站点生成的有效方法是从 Maven 3 生成的工作原型开始，并逐步将功能从 Maven 2 项目转移和测试。一旦你有了完整功能的 Maven 3 项目，你可以稍后将其转换为自己的原型，以充当进一步项目的模板。

### 注意

你可以在[`maven.apache.org/guides/mini/guide-creating-archetypes.html`](http://maven.apache.org/guides/mini/guide-creating-archetypes.html)找到关于构建自己原型的信息。

当从 Maven 2 升级到 3 时，你会发现大多数 JAR 依赖关系和版本都是明确指定的。让我们看一个以下示例：

```
<dependencies>
  <dependency>
    <groupId>junit</groupId>
    <artifactId>junit</artifactId>
      <version>3.8.1</version>
    <scope>test</scope>
  </dependency>
</dependencies>
```

升级是寻找是否可以找到新版本，其中已经修复了错误和已知安全问题的理想时机。Maven 仓库搜索引擎（[`search.maven.org/`](http://search.maven.org/)）是寻找新版本的合适地方。你还可以考虑浏览 [`search.maven.org/#browse`](http://search.maven.org/#browse) 上的仓库，然后点击 JUnit 的链接：

![Maven 2 和 3 的陷阱](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_03_18.jpg)

现在你可以看到不同的版本号和上传日期。在 JUnit 的情况下，我会升级到最新版本；如果由于 API 不兼容而导致构建失败，那么回退到最后一个稳定的点版本，即版本 3.8.2。

## 另请参阅

+   *通过 Maven 运行 Groovy 脚本* 配方

+   *在 Jenkins 中绘制备选代码指标* 配方

+   *基于 JSP 语法错误的 Jenkins 作业失败* 配方


# 第四章：通过 Jenkins 进行沟通

在本章中，我们将涵盖以下配方：

+   使用简单主题插件为 Jenkins 进行皮肤定制

+   使用 WAR 覆盖层对 Jenkins 进行皮肤定制和配置

+   生成主页

+   创建 HTML 报告

+   高效使用视图

+   使用仪表板视图插件节省屏幕空间

+   使用 HTML5 浏览器发出声音

+   用于接待区的极端视图

+   使用 Google 日历进行移动演示

+   适用于 Android 和 iOS 的移动应用程序

+   通过 Google Analytics 了解您的受众

+   使用 R 插件简化强大的可视化

# 介绍

本章探讨了通过 Jenkins 进行沟通，认识到有不同的目标受众。

Jenkins 是一种有才能的沟通工具。其首页显示所有作业的状态，让您能够快速做出决策。您可以轻松设置多个视图，自然地优先考虑信息。Jenkins 具有大量的插件，可以通过电子邮件、仪表板和 Google 服务通知您。它通过移动设备向您发出呼唤，在您经过大屏幕时辐射信息，并用 USB 海绵导弹发射器向您发射。

它的主要受众是开发人员，但不要忘记希望使用正在开发的软件的更广泛受众。定期看到 Jenkins 以一致的视图和公司的外观和感觉进行构建，可以增强对软件路线图的信心。本章包括帮助您触及更广泛受众的配方。

在创建连贯的沟通策略时，有许多 Jenkins 特定的细节需要配置。以下是本章将考虑的一些细节：

+   **通知**：开发人员需要快速了解何时出现问题。Jenkins 有许多插件：您应该选择一些适合团队理念的插件。

+   **页面装饰**：页面装饰器是一种插件，可以向每个页面添加内容。您可以通过添加自己的样式表和 JavaScript 便宜地生成公司的外观和感觉。

+   **覆盖 Jenkins**：使用 Maven WAR 插件，您可以将自己的内容覆盖在 Jenkins 之上。您可以使用此功能添加自定义内容并配置资源，例如主页，从而增强公司的外观和感觉。

+   **优化视图**：前页视图是以选项卡显示的作业列表。受众使用前页快速决定选择哪个作业进行审查。插件扩展了视图类型的选择并优化了信息消化。这可能避免了查找更多信息的需要，节省了宝贵的时间。

+   **随身通知**：极端的视图可以在大型监视器上直观地显示信息。如果您将监视器放置在接待处或咖啡机等地方，那么过路人将会吸收工作状态变化的起伏。这种视图巧妙地暗示了您公司的专业水平和产品路线图的稳定性。

+   **跟踪你的受众群体**：如果你在公开交流，那么你应该跟踪使用模式，以便改进服务。考虑将你的 Jenkins 页面连接到 Google Analytics 或 Piwik，一个开源分析应用程序。

### 提示

**Subversion 存储库**

从本章开始，你将需要一个 Git 或 Subversion 存储库。这将使你能够以最自然的方式使用 Jenkins。为了简洁起见，我们在示例中仅提到 Subversion，但选择 Git 也很容易。如果你还没有存储库，你可以在互联网上注册一些免费或半免费的服务，例如[`www.straw-dogs.co.uk/09/20/6-free-svn-project-hosting-services/`](http://www.straw-dogs.co.uk/09/20/6-free-svn-project-hosting-services/)或 Git 存储库的示例 [`bitbucket.org/`](https://bitbucket.org/)。

或者，你可以考虑在本地设置 Subversion 或 Git。有关 Ubuntu 的安装说明，请访问 [`help.ubuntu.com/community/Subversion`](https://help.ubuntu.com/community/Subversion) 和 [`help.ubuntu.com/lts/serverguide/git.html`](https://help.ubuntu.com/lts/serverguide/git.html)。

# 使用简单主题插件美化 Jenkins

本示例通过主题插件修改了 Jenkins 的外观和感觉。

主题插件是一个页面装饰器：它在每个页面上添加额外的 HTML 标签。该插件允许你上传样式表和 JavaScript 文件。然后通过本地 URL 访问这些文件。然后，每个 Jenkins 页面都使用使用这些 URL 的 HTML 标签装饰。虽然简单，但如果正确制作，视觉效果是强大的。

## 准备工作

安装主题插件（[`wiki.jenkins-ci.org/display/JENKINS/Simple+Theme+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Simple+Theme+Plugin)）。

## 如何操作...

1.  在 Jenkins 的 `userContent` 目录下，创建一个名为 `my.js` 的文件，其中包含以下代码行：

    ```
    document.write("<h1 id='test'>Example Location</h1>")
    ```

1.  在 Jenkins 的 `userContent` 目录中创建一个名为 `mycss.css` 的文件，其中包含以下代码行：

    ```
    @charset "utf-8";
    #test {
      background-image: url(/userContent/camera.png);
    }
    #main-table{
      background-image: url(/userContent/camera.png) !important;
    ```

1.  下载并解压图标存档[`sourceforge.net/projects/openiconlibrary/files/0.11/open_icon_library-standard-0.11.tar.bz2/download`](http://sourceforge.net/projects/openiconlibrary/files/0.11/open_icon_library-standard-0.11.tar.bz2/download)并查看可用图标。或者，你可以使用书籍网站下载的图标。将图标添加到 `userContent` 目录并将其重命名为 `camera.png`。

1.  访问 Jenkins 的主配置页面：`/configure`。在 **Theme** 部分下，填写 CSS 和 JavaScript 文件的位置：

    +   **主题 CSS 的 URL**：`/userContent/myjavascript.css`

    +   **主题 JS 的 URL**：`/userContent/mycss.js`

1.  点击 **保存**。

1.  返回 Jenkins 主页并查看你的工作，如下截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_01.jpg)

## 工作原理...

简单主题插件是一个页面装饰器。它向每个页面添加以下信息：

```
<script>
<link rel="stylesheet" type="text/css" href="/userContent/mycss.css" /><script src="img/myjavascript.js" type="text/javascript">
</script>
```

JavaScript 在生成的页面顶部附近写入一个带有`id="test"`的标题。通过 CSS 定位符`#test`触发级联样式表规则会将相机图标添加到背景中。

图片尺寸未经调整，不适合屏幕顶部；它们被浏览器裁剪。这是一个你可以通过实验来解决的问题。

第二个 CSS 规则针对`main-table`触发，这是 Jenkins 生成的标准首页的一部分。完整的相机图标显示在那里。

当访问 Jenkins 的其他部分时，您会注意到相机图标看起来不合适，而且过大。您需要时间修改 CSS 和 JavaScript 来生成更好的效果。通过小心和自定义代码，您可以使 Jenkins 适应公司形象。

### 提示

**CSS 3 怪癖**

各种浏览器类型和版本在支持各种 CSS 标准上存在一些怪异之处。有关概述，请访问[`www.quirksmode.org/css/contents.html`](http://www.quirksmode.org/css/contents.html)。

## 还有更多...

这里还有一些需要考虑的事情。

### CSS 3

CSS 3 有许多功能。要在 JavaScript 生成的标题周围绘制按钮，请将 CSS 文件中的`#test`部分更改为以下代码：

```
#test {
  width: 180px; height: 60px;
  background: red; color: yellow;
  text-align: center;
  -moz-border-radius: 40px; -webkit-border-radius: 40px;
}
```

使用 Firefox，CSS 规则生成了以下按钮：

![CSS 3](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_02.jpg)

### 注意

对于急于行动的人，你可以在 Smashing Magazine 网站上下载 CSS 3 技巧表：[`coding.smashingmagazine.com/wp-content/uploads/images/css3-cheat-sheet/css3-cheat-sheet.pdf`](http://coding.smashingmagazine.com/wp-content/uploads/images/css3-cheat-sheet/css3-cheat-sheet.pdf)

### 包含的 JavaScript 库框架

Jenkins 使用 YUI 库[`yuilibrary.com/`](http://yuilibrary.com/)。在每个 HTML 页面中装饰，核心 YUI 库(`/scripts/yui/yahoo/yahoo-min.js`)已经准备好以供重复使用。然而，许多 web 开发人员习惯于 jQuery。你也可以通过安装 jQuery 插件（[`wiki.jenkins-ci.org/display/JENKINS/jQuery+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/jQuery+Plugin)）来包含此库。你还可以考虑通过 WAR 叠加层将你喜欢的 JavaScript 库添加到 Jenkins 的`/scripts`目录中（参见下一个示例）。

### 信而验证

伴随着巨大的能力而来的是巨大的责任。如果只有少数管理员维护您的 Jenkins 部署，则您很可能信任每个人都可以添加 JavaScript 而不会产生有害的副作用。然而，如果有大量管理员使用各种各样的 Java 库，则您的维护和安全风险会迅速增加。请考虑您的安全策略，并至少添加审计追踪插件（[`wiki.jenkins-ci.org/display/JENKINS/Audit+Trail+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Audit+Trail+Plugin)）以跟踪行动。

## 另请参阅

+   *使用 WAR 覆盖为 Jenkins 进行换肤和资源配置* 配方

+   *生成主页* 配方

# 使用 WAR 覆盖为 Jenkins 进行换肤和资源配置

本配方描述了如何将内容覆盖到 Jenkins WAR 文件上。通过 WAR 覆盖，你可以更改 Jenkins 的外观和感觉，以进行企业品牌化和主页内容配置。本示例基本上只添加了自定义的 `favicon.ico`（在网页浏览器地址栏中的图标）。包含更多内容几乎不需要额外的努力。

Jenkins 将其版本作为依赖项保存在 Maven 仓库中。你可以使用 Maven 拉取 WAR 文件，展开它，添加内容，然后重新打包。这使你能够提供资源，如图像、主页、地址栏中称为 `fav` 图标的图标，以及影响搜索引擎浏览你内容的 `robots.txt`。

要小心：如果 Jenkins 的结构和图形内容随时间发生根本性变化，使用 WAR 覆盖将很便宜。然而，如果覆盖物破坏了结构，那么你可能要进行详细的功能测试才能发现这一点。

你还可以考虑通过 WAR 覆盖进行最小更改，也许只更改 `favicon.ico`，添加图像和 `userContent`，然后使用简单主题插件（参见前面的配方）进行样式设置。

## 准备工作

创建名为 `ch4.communicating/war_overlay` 的目录以存放此配方中的文件。

## 如何实现...

1.  浏览到 Maven 仓库 [`repo.jenkins-ci.org/releases/org/jenkins-ci/main/jenkins-war/`](http://repo.jenkins-ci.org/releases/org/jenkins-ci/main/jenkins-war/) 并查看 Jenkins 的依赖项。

1.  创建以下 `pom.xml` 文件。随意更新为更新版本的 Jenkins：

    ```
    <project  
    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>nl.uva.berg</groupId>
    <artifactId>overlay</artifactId>
    <packaging>war</packaging>
    <!-- Keep version the same as Jenkins as a hint -->
    <version>1.437</version>
    <name>overlay Maven Webapp</name>
    <url>http://maven.apache.org</url>
    <dependencies>
    <dependency>
    <groupId>org.jenkins-ci.main</groupId>
    <artifactId>jenkins-war</artifactId>
    <version>1.437</version>
    <type>war</type>
    <scope>runtime</scope>
    </dependency>
    </dependencies>
    <repositories>
    <repository>
          <id>Jenkins</id>
          <url>http://repo.jenkins-ci.org/releases</url>
         </repository>
    </repositories>
    </project>
    ```

1.  访问 `favicon.ico` 生成网站，例如 [`www.favicon.cc/`](http://www.favicon.cc/)。按照其说明，创建你自己的 `favicon.ico`。或者，使用提供的示例。

1.  将 `favicon.ico` 添加到 `src/main/webapp` 位置。

1.  创建目录 `src/main/webapp/META-INF` 并添加一个名为 `context.xml` 的文件，其中包含以下一行代码：

    ```
    <Context logEffectiveWebXml="true" path="/"></Context>
    ```

1.  在你的顶层目录中，运行以下命令：

    ```
    mvn package
    ```

1.  在新生成的目标目录中，你将看到 WAR 文件 `overlay-1.437.war`。检查内容，验证你是否已修改了 `favicon.ico`。

1.  [可选] 部署 WAR 文件到本地 Tomcat 服务器，验证并浏览更新后的 Jenkins 服务器：![如何实现...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_03.jpg)

## 工作原理...

Jenkins 通过中央 Maven 仓库公开了其 WAR 文件。这允许你通过标准的 Maven 依赖管理拉取 Jenkins 的特定版本。

Maven 使用约定。它期望在 `src/main/webapp` 或 `src/main/resources` 中找到要覆盖的内容。

`context.xml` 文件定义了 Web 应用程序的某些行为，例如数据库设置。在此示例中，设置 `logEffectiveWebXML` 要求 Tomcat 在应用程序启动时记录特定信息（[`tomcat.apache.org/tomcat-7.0-doc/config/context.html`](http://tomcat.apache.org/tomcat-7.0-doc/config/context.html)）。 Jenkins Wiki 推荐了此设置（[`wiki.jenkins-ci.org/display/JENKINS/Installation+via+Maven+WAR+Overlay`](https://wiki.jenkins-ci.org/display/JENKINS/Installation+via+Maven+WAR+Overlay)）。该文件放置在 `META-INF` 目录中，因为 Tomcat 可以在此处获取设置而无需重新启动服务器。

`<packaging>war</packaging>` 标签告诉 Maven 使用 WAR 插件进行打包。

您在最终叠加 WAR 的名称中使用了与原始 Jenkins WAR 版本相同的版本号。这样可以更容易地发现 Jenkins 版本是否更改。这再次凸显了使用惯例有助于提高可读性并减少错误机会。在从验收环境部署到生产环境时，应删除版本号。

在 `pom.xml` 文件中，您将 [`repo.jenkins-ci.org/releases`](http://repo.jenkins-ci.org/releases) 定义为查找 Jenkins 的存储库。

Jenkins WAR 文件作为 `war` 类型的依赖项和 `runtime` 范围的依赖项引入。运行时范围表示该依赖项不需要进行编译，但是需要执行。有关作用域的更详细信息，请参阅 [`maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Dependency_Scope`](http://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Dependency_Scope)。

有关 WAR 叠加的更多详细信息，请参阅 [`maven.apache.org/plugins/maven-war-plugin/index.html`](http://maven.apache.org/plugins/maven-war-plugin/index.html)。

### 提示

**避免工作

为了减少维护工作量，最好安装额外的内容，而不是替换可能在其他地方或由第三方插件使用的内容。

## 还有更多...

如果您希望完全修改 Jenkins 的外观和感觉，则需要涵盖许多细节。以下部分提及了一些细节。

### 您可以替换哪些类型的内容？

Jenkins 服务器部署到两个主要位置。第一个位置是核心应用程序，第二个位置是存储更改信息的工作空间。为了更全面地了解内容，请查看目录结构。Linux 中一个有用的命令是 tree 命令，它显示目录结构。要在 Ubuntu 下安装，请使用以下命令：

```
apt-get install tree

```

对于 Jenkins Ubuntu 工作空间，使用以下命令生成工作空间的树状视图：

```
tree –d –L 1 /var/lib/Jenkins

```

**├── 指纹**（用于存储文件的校验和以唯一标识文件）

**├── 工作**（存储作业配置和构建结果）

**├── 插件**（插件部署和通常配置的位置）

**├── tools**（部署 Maven 和 Ant 等工具的位置）

**├── updates**（更新）

**├── userContent**（在`/userContent` URL 下提供的内容）

**└── users**（显示在`/me` URL 下的用户信息）

Web 应用程序的默认 Ubuntu 位置是`/var/run/jenkins/war`。如果您从命令行运行 Jenkins，则放置 Web 应用程序的选项是：

```
–webroot

```

**├── css**（Jenkins 样式表的位置）

**├── executable**（用于从命令行运行 Jenkins）

**├── favicon.ico**（在此方法中替换的图标）

**├── help**（帮助内容目录）

**├── images**（不同尺寸的图形）

**├── META-INF**（manifes 文件和生成的 WAR 的`pom.xml`文件的位置）

**├── robots.txt**（用于告诉搜索引擎允许爬行的位置）

**├── scripts**（JavaScript 库位置）

**├── WEB-INF**（Web 应用程序的 servlet 部分的主要位置）

**└── winstone.jar**（Servlet 容器：[`winstone.sourceforge.net/`](http://winstone.sourceforge.net/)）

### 搜索引擎和 robots.txt

如果您要添加自己的自定义内容，例如用户主页、公司联系信息或产品详情，请考虑修改顶级`robots.txt`文件。目前，它将搜索引擎从所有内容中排除在外：

```
# we don't want robots to click "build" links
User-agent: *
Disallow: /
```

您可以在[`www.w3.org/TR/html4/appendix/notes.html#h-B.4.1.1`](http://www.w3.org/TR/html4/appendix/notes.html#h-B.4.1.1)找到`robots.txt`结构的完整详情。

Google 使用更丰富的结构，允许和禁止；请参阅[`developers.google.com/webmasters/control-crawl-index/docs/robots_txt?csw=1`](https://developers.google.com/webmasters/control-crawl-index/docs/robots_txt?csw=1)

下面的`robots.txt`允许 Google 爬虫访问`/userContent/corporate/`目录。所有网络爬虫是否会遵守意图尚不确定。

```
User-agent: *
Disallow: /
User-agent: Googlebot
Allow: /userContent/corporate/
```

### 注意

为了帮助保护您的 Jenkins 基础架构，请参考第二章中的方法，*Enhancing Security*。

## 另请参阅

+   用简单主题插件为 Jenkins 设置样式的方法

+   *生成主页*的方法

# 生成主页

用户的主页是表达您组织身份的好地方。您可以创建一致的外观和感觉，表达您团队的精神。

本方法将探讨位于`/user/userid`目录下的主页的操作，并由用户通过 Jenkins `/me` URL 配置。

### 注意

值得审查的类似插件是 Gravatar 插件。您可以在[`wiki.jenkins-ci.org/display/JENKINS/Gravatar+plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Gravatar+plugin)找到插件主页

## 准备工作

安装 Avatar 插件（[`wiki.jenkins-ci.org/display/JENKINS/Avatar+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Avatar+Plugin)）。

为用户 `fakeuser` 创建一个 Jenkins 帐户。 您可以配置 Jenkins 以使用许多身份验证策略；选择将影响您如何创建用户。 一个例子是使用 *Reviewing project-based matrix tactics via a custom group script* 中详细介绍的基于项目的矩阵策略，位于 Chapter 2，*Enhancing Security* 中的配方。

### 注意

除非作为 Jenkins 管理员您在 **Configure Global Security** 页面下配置了 **Markup Formatter** 为 **Raw**，否则您将无法使此配方起作用。 通过这样做，您允许任何可以编辑描述的人注入他们自己的脚本代码。 如果您是一个非常信任的小型开发团队，这可能是一种可行的做法。 但是，一般来说，考虑这是一个安全问题。

## 如何操作...

1.  浏览到 [`en.wikipedia.org/wiki/Wikipedia:Public_domain_image_resources`](http://en.wikipedia.org/wiki/Wikipedia:Public_domain_image_resources) 以获取图片的公共领域来源列表。

1.  在 [`commons.wikimedia.org/wiki/Main_Page`](http://commons.wikimedia.org/wiki/Main_Page) 搜索开源图像。

1.  通过点击以下截图中显示的 **Download Image File: 75 px** 链接，从 [`commons.wikimedia.org/wiki/File%3ACharles_Richardson_(W_H_Gibbs_1888).jpg`](http://commons.wikimedia.org/wiki/File%3ACharles_Richardson_(W_H_Gibbs_1888).jpg) 下载图像：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_04.jpg)

    ### 注意

    如果图像不再可用，请选择另一个。

1.  以 `fakeuser` 身份登录到您的 Jenkins 服务器并访问其配置页面，地址为 `http://localhost:8080/user/fakeuser/configure`。

1.  在 **Avatar** 部分上传图像：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_05.jpg)

1.  查看 URL `http://localhost:8080/user/fakeuser/avatar/image`。

    ### 注意

    现在，您随时都可以使用此已知的 URL 来显示您的头像。

1.  将以下文本添加到用户配置文件描述中：

    ```
    <script type="text/JavaScript">
    functionchangedivview()
    {
    var elem=document.getElementById("divid");
    elem.style.display=(elem.style.display=='none')?'block':'none';
    }
    </script>
    <h2>OFFICIAL PAGE</h2>
    <div id="divid">
    <table border=5 bgcolor=gold><tr><td>HELLO WORLD</td></tr></table>
    </div>
    <a href="javascript:;" onClick="changedivview();">Switch</a>  
    ```

1.  访问 `/user/fakeuser` 页面。 您将在描述中看到一个名为 **Switch** 的链接。 如果您点击该链接，则 **HELLO WORLD** 内容将会出现或消失。

1.  复制 `fakeuser` 的用户目录到一个名为 `fakeuser2` 的目录，例如，`/var/lib/jenkins/user/fakeuser`。 在 `fakeuser2` 目录中找到的 `config.xml` 文件中，将 `<fullName>` 标签的值从 `fakeuser` 更改为 `fakeuser2`。 将 `<emailAddress>` 的值更改为 `fakeuser2@dev.null`。

1.  以 `fakeuser2` 的身份登录，密码与 `fakeuser` 相同。

1.  访问主页 `/user/fakeuser2`。 注意电子邮件地址的更新。

## 它是如何工作的...

Avatar 插件允许您将图像上传到 Jenkins。 图像的 URL 位于固定位置。 您可以通过简单的主题插件重复使用它，以添加内容而不使用 WAR 覆盖。

有大量的公共领域和开源图片可供免费使用。在生成自己的内容之前，值得在互联网上查看资源。如果你创建内容，请考虑捐赠给开源存档，比如[archive.org](http://archive.org)。

除非你过滤掉 HTML 标签和 JavaScript 的描述（参见第三章 *构建软件* 中的 *通过构建描述公开信息* 这一做法），否则你可以使用自定义 JavaScript 或 CSS 动画来为个性化的 Jenkins 添加吸引眼球的效果。

你的`fakeuser`信息存储在`/user/fakeuser/config.xml`中。通过将其复制到另一个目录并略微修改`config.xml`文件，你创建了一个新的用户帐户。这种格式易于阅读，并且易于结构化成用于创建更多帐户的模板。你创建了`fakeuser2`帐户来证明这一点。

通过使用 WAR 覆盖配方并添加额外的`/user/username`目录，其中包含自定义的`config.xml`文件，你可以控制 Jenkins 用户群体，例如，从一个中央配置脚本或在第一次登录尝试时，使用自定义授权脚本（参见第二章 *增强安全性* 中的 *使用脚本领域认证进行配置的做法*）。

## 更多内容……

通过使用模板`config.xml`来强制执行一致性。这将强制执行更广泛的统一结构。你可以将初始密码设置为已知值或空值。只有在用户从创建到首次登录的时间非常短的情况下，空密码才有意义。你应该考虑这是一种不好的做法，是一个等待发生问题的问题。

描述存储在描述标签下。内容以 URL 转义文本形式存储。例如，`<h1>描述</h1>`存储为：

```
<description>&lt;h1&gt;DESCRIPTION&lt;/h1&gt;</description>
```

许多插件也将它们的配置存储在同一个`config.xml`文件中。随着你在 Jenkins 服务器中增加插件的数量，这是很自然的，因为你了解了这个产品，你需要偶尔审查你的模板的完整性。

## 另请参阅

+   *使用简单主题插件装饰 Jenkins 的做法*

+   *使用 WAR 覆盖的皮肤和提供 Jenkins 的做法*

+   在第二章 *增强安全性* 中的 *通过自定义组脚本审查基于项目矩阵的策略* 这一做法

# 创建 HTML 报告

作业仪表板左侧菜单是有价值的房地产。开发者的眼睛自然会扫描这个区域。这个教程描述了如何将自定义 HTML 报告的链接添加到菜单中，以便更快地注意到报告。

## 准备工作

安装 HTML 发布者插件（[`wiki.jenkins-ci.org/display/JENKINS/HTML+Publisher+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/HTML+Publisher+Plugin)）。我们假设你有一个已提交了 Packt 代码的 Subversion 仓库。

## 怎么做…

1.  创建一个自由风格的软件项目，并将其命名为`ch4.html_report`。

1.  在**源代码管理**部分下，单击**Subversion**。

1.  在**模块**部分下，将`Repo/ch4.communicating/html_report`添加到**存储库 URL**，其中`Repo`是您的子版本存储库的 URL。

1.  在**构建后操作**部分下，检查**发布 HTML 报告**。 添加以下详细信息：

    +   **要存档的 HTML 目录**：`target/custom_report`

    +   **索引页面[s]**：`index.html`

    +   **报告标题**：`My HTML Report`

    +   选中**保留过去的 HTML 报告**复选框

1.  单击**保存**。

1.  运行作业并查看左侧菜单。 现在您将看到一个指向您报告的链接，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_06.jpg)

## 工作原理...

您的子版本存储库包含一个`index.html`文件，该文件被拉入作业的工作区。 插件按照广告中的方式运行，并添加了一个指向 HTML 报告的链接。 这使得您的受众可以有效地找到您生成的自定义信息。

## 还有更多...

示例报告如下所示：

```
<html><head><title>Example Report</title>
<link rel="stylesheet" type="text/css" href="/css/style.css" /></head>
<body>
<h2>Generated Report</h2>
Example icon: <img title="A Jenkins Icon" alt="Schedule a build" src="img/clock.png" />
</body></html>
```

它拉取了主 Jenkins 样式表`/css/style.css`。

当您在应用程序中更新样式表时，可能会出现在清除浏览器缓存之前看不到更改的情况。 Jenkins 以一种巧妙的方式解决了这个延迟问题。 它使用一个带有每个 Jenkins 版本都会更改的唯一数字的 URL。 例如，对于`css`目录，您有两个 URL：

+   `/css`

+   `/static/uniquenumber/css`

大多数 Jenkins URL 使用后一种形式。 考虑为您的样式表也这样做。

### 注意

每个版本的唯一编号都会更改，因此您需要为每次升级更新 URL。

在 Maven 构建中运行`site`目标时，将生成一个本地网站（[`maven.apache.org/plugins/maven-site-plugin`](http://maven.apache.org/plugins/maven-site-plugin)）。 此网站在 Jenkins 作业内有一个固定的 URL，您可以使用**My HTML Report**链接指向它。 这使得诸如测试结果之类的文档易于访问。

## 另请参阅

+   *高效使用视图*配方

+   *使用 Dashboard View 插件节省屏幕空间* 配方

# 高效使用视图

Jenkins 具有令人上瘾的易配置性，非常适合创建大量作业。 这会增加开发人员暴露的信息量。 Jenkins 需要通过有效地利用浏览器空间来避免混乱。 一种方法是定义最小化视图。 在本配方中，您将使用 DropDown ViewsTabBar 插件。 它将视图作为标签删除，并用一个选择框替换这些标签。 这有助于更快地导航。 您还将看到如何使用脚本生成的简单 HTML 表单快速提供大量作业。

### 提示

在本配方中，您将创建大量视图，稍后可能需要删除。 如果您使用的是虚拟盒映像，请考虑克隆映像，并在完成后将其删除。

## 准备工作

安装 DropDown ViewsTabBar 插件 ([`wiki.jenkins-ci.org/display/JENKINS/DropDown+ViewsTabBar+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/DropDown+ViewsTabBar+Plugin))。

## 如何操作...

1.  复制并粘贴以下 Perl 脚本到一个名为`create.pl`的可执行文件中：

    ```
    #!/usr/bin/perl
    $counter=0;
    $end=20;
    $host='http://localhost:8080';
    while($end > $counter){
      $counter++;
      print "<form action=$host/createItem?mode=copy method=POST>\n";
      print "<input type=text name=name value=CH4.fake.$counter>\n";
      print "<input type=text name=from value=Template1 >\n";
      print "<input type=submit value='Create CH4.fake.$counter'>\n";
      print "</form><br>\n";
      print "<form action=$host/job/CH4.fake.$counter/doDelete method=POST>\n";
      print "<input type=submit value='Delete CH4.fake.$counter'>\n";
      print "</form><br>\n";
    }
    ```

1.  根据 Perl 脚本的输出创建一个 HTML 文件，例如：

    ```
    perl create.pl > form.html
    ```

1.  在网页浏览器中，以管理员身份登录 Jenkins。

1.  创建作业`Template1`，添加任何您希望的细节。这是您将复制到许多其他作业中的模板作业。

1.  在同一个浏览器中加载`form.html`。

1.  点击其中一个**创建 CH4.fake**按钮。Jenkins 返回一个错误消息：

    ```
    HTTP ERROR 403 Problem accessing /createItem. Reason:
    No valid crumb was included in the request
    ```

1.  访问`http://localhost:8080/configureSecurity`上的**配置全局安全性**，取消勾选**防止跨站请求伪造漏洞**框。

1.  点击**保存**。

1.  点击所有的**创建 CH4.fake**按钮。

1.  访问 Jenkins 的首页，验证作业已经创建并基于`Template1`作业。

1.  创建大量视图，并随机选择作业。查看首页，注意混乱。

1.  访问配置屏幕`/configure`，在**视图选项卡栏提供下拉菜单以选择视图**中的**视图选项卡栏**下拉框中选择**DropDownViewsTabBar**。在**DropDownViewsTabBar**的子部分中，勾选**显示作业计数**框，如下图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_07.jpg)

1.  点击**保存**按钮：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_08.jpg)

1.  在 Jenkins 中，访问**配置全局安全性**`http://localhost:8080/configureSecurity`，并勾选**防止跨站请求伪造漏洞**框。

1.  点击**保存**。

## 工作原理是...

只要 Jenkins 中的面包屑安全功能关闭，该表单就能正常工作。当开启此功能时，它会生成一个随机数，表单在提交时必须返回该随机数。这样 Jenkins 就知道该表单是与服务器进行的有效对话的一部分。生成的 HTTP 状态错误在 4xx 范围内，这意味着客户端输入无效。如果 Jenkins 返回了 5xx 错误，则意味着服务器错误。因此，在提交我们自己的数据时，我们不得不关闭此功能。我们不建议在生产环境中这样做。

一旦您以管理员身份登录 Jenkins，您可以创建作业。您可以通过 GUI 或通过发送 POST 信息来执行此操作。在本教程中，我们将一个名为`Template1`的作业复制到以`CH4.fake`开头的新作业中，如下所示：

```
<form action=http://localhost:8080/createItem?mode=copy method=POST>
<input type=text name=name value=CH4.fake.1>
<input type=text name=from value=Template1 >
<input type=submit value='Create CH4.fake.1'>
</form>
```

您使用的 POST 变量是`name`用于新作业的名称，`from`用于模板作业的名称。POST 操作的 URL 是`/createItem?mode=copy`。

要更改主机名和端口号，您需要更新 Perl 脚本中找到的`$host`变量。

要删除一个作业，Perl 脚本生成的表单中的操作指向`/job/Jobname/doDelete`（例如，`/job/CH4.fake.1/doDelete`）。不需要额外的变量。

要增加表单条目的数量，您可以更改变量`$end`的值为`20`。

## 还有更多...

Jenkins 使用标准库 Stapler ([`stapler.kohsuke.org/what-is.html`](http://stapler.kohsuke.org/what-is.html))将服务绑定到 URL。插件也使用 Stapler。当您安装插件时，潜在的操作数量也会增加。这意味着您可以通过类似于本文中的 HTML 表单激活许多操作。您将在第七章中发现，使用 Stapler 编写绑定代码所需的工作量很小，*探索插件*。

## 另见

+   *使用仪表板视图插件节省屏幕空间* 步骤

# 使用仪表板视图插件节省屏幕空间

在*高效使用视图*步骤中，您发现可以使用 Views 插件节省水平选项卡空间。在这个步骤中，您将使用 Dashboard View 插件来压缩水平空间的使用。压缩水平空间有助于高效吸收信息。

仪表板视图插件允许您配置视图的区域以显示特定功能，例如作业的网格视图或显示失败作业子集的区域。用户可以在屏幕上拖放这些区域。

### 注意

开发人员已经使仪表板易于扩展，因此稍后会有更多选择。

## 准备工作

安装仪表板视图插件 ([`wiki.jenkins-ci.org/display/JENKINS/Dashboard+View`](https://wiki.jenkins-ci.org/display/JENKINS/Dashboard+View))。要么手动创建一些作业，要么使用上一个步骤中提供的 HTML 表单创建作业。

## 操作步骤...

1.  作为 Jenkins 管理员，登录到 Jenkins 实例的主页。

1.  点击屏幕顶部的第二个标签页上的**+**号创建一个新视图。

1.  选择**仪表板**视图。

1.  在**作业**部分，选择一些您的虚拟作业。

1.  将**仪表板控件**保留为默认设置。

1.  点击**确定**。您现在将看到一个空白的视图屏幕。

1.  在左侧菜单中，点击**编辑视图**链接。

1.  在视图的**仪表板控件**部分，选择以下内容：

    +   将仪表板控件添加到视图顶部：**- 作业网格**

    +   将仪表板控件添加到视图底部：**- 不稳定的作业**

1.  在配置屏幕底部，点击**确定**按钮。现在您将看到**仪表板**视图: ![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_09.jpg)

您可以使用箭头图标扩展或收缩功能区域：

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_10.jpg)

## 工作原理...

仪表板插件将屏幕划分为不同的区域。在仪表板配置期间，您可以选择作业网格和不稳定的作业控件。其他仪表板控件包括作业列表、最新构建、从属统计、测试统计图或网格以及测试趋势图。随着插件的成熟，将会有更多的选择。

与其他视图相比，**作业网格**控件节省空间，因为显示的作业密度很高。

### 提示

如果你还在使用 **Many Views** 标签（请参阅前面的教程），可能会有一点小问题。当你点击仪表板标签时，会显示原始的视图集，而不是选择框。

## 还有更多...  

仪表板插件提供了一个框架，供其他插件开发者创建仪表板视图。这种用法的一个例子是项目统计插件 ([`wiki.jenkins-ci.org/display/JENKINS/Project+Statistics+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Project+Statistics+Plugin))。

## 另请参阅

+   *创建 HTML 报告* 教程

+   *高效使用视图* 教程

# 使用 HTML5 浏览器发出声音

这个教程描述了如何在 Jenkins 用户的浏览器中发送自定义声音，当事件发生时，比如一个成功的构建。你也可以在任意时间发送声音消息。这不仅适用于喜欢被名人唱歌或者大喊的开发者，也适用于在大型服务器群中寻找计算机的系统管理员。

## 准备工作

安装 Jenkins 声音插件 ([`wiki.jenkins-ci.org/display/JENKINS/Jenkins+Sounds+plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Jenkins+Sounds+plugin))。确保已安装兼容的网络浏览器，如最新版本的 Firefox 或 Chrome。

### 注意

若要了解更多关于浏览器中的 HTML5 兼容性的详细信息，请考虑查阅：[`en.wikipedia.org/wiki/Comparison_of_layout_engines_%28HTML5%29`](http://en.wikipedia.org/wiki/Comparison_of_layout_engines_%28HTML5%29)。

## 如何做...

1.  以 Jenkins 管理员身份登录，访问**配置系统**屏幕`/configure`。

1.  在**Jenkins 声音**部分，勾选**通过启用 HTML5 音频浏览器播放**。

    ### 注意

    如果 Jenkins 在查找声音存档时出现问题，例如错误消息中出现`文件未找到 'file:/C:/Users/Alan/.jenkins/jar:file:/C:/Users/Alan/.jenkins/plugins/sounds/WEB-INF/lib/classes.jar/sound-archive.zip'`，那么解压`classes.jar`文件，并将`sounds-archive.zip`文件移动到错误消息中提到的相同目录中。最后，将配置指向存档，例如`file:/C:/Users/Alan/.jenkins/plugins/sounds/WEB-INF/lib/sound-archive.zip`。

1.  点击**保存**按钮。

1.  选择位于 Jenkins 主页上的**Job creation**链接。

1.  创建一个名为 `ch4.sound` 的**新作业**。

1.  选择**构建一个自由风格的软件项目**。

1.  点击**确定**。

1.  在**后构建操作**部分，勾选**Jenkins 声音**选项。

1.  添加两个声音：**EXPLODE** 和 **doh**：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_11.jpg)

1.  点击**保存**。

1.  点击**立即构建**链接。

1.  成功时，你的浏览器将播放`EXPLODE`wav 文件。

1.  编辑你的作业，使其失败，例如添加一个不存在的源代码仓库。

1.  再次构建任务。失败时，你的网络浏览器将播放`doh`wav 文件。

## 工作原理...

你已成功配置了你的作业，根据构建的成功或失败播放不同的声音。

您还可以通过配置哪些事件转换将触发声音来进一步优化插件的反应，例如，如果前一个构建结果是失败，当前构建结果是成功。这在**对于上一个构建结果**一组复选框中定义。

该插件作为页面装饰器工作。它添加了以下异步轮询新声音的 JavaScript。您的浏览器正在执行大部分工作，释放服务器资源：

```
<script src="img/script" type="text/javascript"></script><script type="text/javascript" defer="defer">function _sounds_ajaxJsonFetcherFactory(onSuccess, onFailure) {
  return function() {
    newAjax.Request("/sounds/getSounds", {
      parameters: { version: VERSION },
      onSuccess: function(rsp) {
        onSuccess(eval('x='+rsp.responseText))
      },
      onFailure: onFailure
    });
  }
} 
if (AUDIO_CAPABLE) {
    _sounds_pollForSounds(_sounds_ajaxJsonFetcherFactory);
}</script>
```

## 还有更多...

该声音插件还允许您向连接的网络浏览器流式传输任意声音。这不仅对于恶作剧和针对您分布式团队的激励演讲有用，还可以执行诸如在重新启动服务器之前发出 10 分钟警告警报等有用操作。

您可以在[`www.archive.org/details/opensource_audio`](http://www.archive.org/details/opensource_audio)找到一些不错的音乐收藏。

例如，您可以在[`www.archive.org/details/OpenPathMusic44V2`](http://www.archive.org/details/OpenPathMusic44V2)找到一份“每个孩子一台笔记本电脑”音乐库的副本。在收藏中，您将发现`shenai.wav`。首先，将声音添加到互联网上的某个地方，以便找到。一个好的地方是 Jenkins 的`userContent`目录。要在任何连接的网络浏览器上播放声音，您需要访问触发地址（将`localhost:8080`替换为您自己的地址）：

`http://localhost:8080/sounds/playSound?src=http://localhost:8080/userContent/shenai.wav`

## 另请参阅

+   在第一章中的 *Maintaining Jenkins*，*通过 Firefox 与 Jenkins 保持联系* 配方

# 接待区的极端观点

敏捷项目强调沟通的作用胜过于文档的需求。**信息辐射器**有助于快速获得反馈。信息辐射器具有两个主要特征：它们随时间变化，并且呈现的数据易于消化。

eXtreme Feedback Panel 插件是信息辐射器的一个示例。它是一个高度视觉化的 Jenkins 视图。如果布局格式一致，并在大型监视器上显示，则非常适合此任务。还将其视为对您的开发流程的积极广告。您可以将其显示在接待处后面，或者放在一个受欢迎的社交区域，例如靠近咖啡机或项目室。

在此配方中，您将添加 eXtreme Feedback Panel 插件，并通过描述中的 HTML 标签修改其外观。

## 准备工作

安装 eXtreme Feedback Panel 插件（[`wiki.jenkins-ci.org/display/JENKINS/eXtreme+Feedback+Panel+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/eXtreme+Feedback+Panel+Plugin)）。

## 如何做...

1.  创建一个名为`Blackboard Report Pro Access`的作业，并添加以下描述：

    ```
    <center>
    <p>Writes Blackboard sanity reports<br>
    and sends them to a list.
    <table border="1" class="myclass"><tr><td>More Details</td></tr></table>
    </center>
    ```

1.  创建一个名为`eXtreme`的新视图（`/newView`）。选中 **eXtremeFeedBack Panel**，然后点击 **OK**。

1.  选择 6-24 个已经创建的作业，包括本配方中之前创建的作业。

1.  将列数设置为**2**。

1.  将刷新时间设置为**20**秒。

1.  点击**显示作业描述**。

1.  点击**确定**。

1.  尝试设置（特别是字体像素大小）。优化视图取决于使用的显示器以及观众观看显示器的距离，如下图所示：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_12.jpg)

## 它的工作原理...

设置和运行这个信息辐射器很容易。结果呈现了软件流程动态的精美视图。

将刷新率设置为 20 秒存在争议。更新之间的长时间延迟会降低观看者的兴趣。

你已经写了一个描述，在极端视图中部分格式化，但在作业配置页面和 Jenkins 的其他位置中是 HTML 转义的。你可以看到信息区比其他项目更容易消化。这突显了编写一致描述的必要性，这些描述遵循内部惯例，并且在一定长度以下，以自然地适应屏幕。为工作取一个更长、更具描述性的名称有助于观众更好地理解工作的背景。

### 注意

通过 URL `http://localhost:8080/view/Jobname/configure`快速配置视图，将`Jobname`中的任何空格替换为`%20`。

## 还有更多...

信息辐射器有趣且形态各异。从在大型显示器上显示不同视图，到 USB 海绵导弹的发射和名人的声音滥用（参见*使用 HTML5 浏览器制造噪音*配方）。

Jenkins 中值得探索的一些示例电子项目包括：

+   **熔岩灯**：[`wiki.jenkins-ci.org/display/JENKINS/Lava+Lamp+Notifier`](https://wiki.jenkins-ci.org/display/JENKINS/Lava+Lamp+Notifier)

+   **USB 导弹发射器**：[`github.com/codedance/Retaliation`](https://github.com/codedance/Retaliation)

+   **交通灯**：[`code.google.com/p/hudsontrafficlights/`](http://code.google.com/p/hudsontrafficlights/)

记住，让我们小心一些。

## 另请参阅

+   *使用仪表板视图插件节省屏幕空间*配方

+   *使用 HTML5 浏览器制造噪音*配方

# 使用 Google 日历进行移动演示

Jenkins 插件可以将构建历史推送到不同的知名社交媒体服务。现代 Android 或 iOS 手机预装了这两种服务的应用程序，降低了采用的门槛。在这个配方中，我们将配置 Jenkins 与 Google 日历一起工作。

## 准备工作

下载并安装 Google 日历插件（[`wiki.jenkins-ci.org/display/JENKINS/Google+Calendar+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Google+Calendar+Plugin)）。确保你有一个用于 Gmail 的测试用户帐户。

## 如何做...

1.  登录 Gmail 并访问**日历**页面。

1.  通过单击**添加**链接在**我的日历**部分下创建新的日历。

1.  添加日历名称 `Test for Jenkins`。

1.  点击 **创建日历**。默认情况下，新日历是私有的。暂时保持私有。

1.  在 **我的日历** 部分，点击 **Test for Jenkins** 旁边的向下图标。选择 **日历设置** 选项。

1.  在 XML 按钮上右键单击 **复制链接位置**：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_13a.jpg)

1.  查看 **嵌入此日历** 部分。它描述了如何将您的日历添加到网页中。将提供的代码复制并粘贴到空的 HTML 页面中。保存并在 web 浏览器中查看。

1.  以管理员身份登录 Jenkins。

1.  创建一个名为 `Test_G` 的新作业。

1.  在 **构建后** 部分，勾选 **将作业状态发布到 Google 日历**。

1.  将您从 XML 按钮复制的日历详细信息添加到 **日历网址** 文本框中。

1.  添加您的 Gmail 登录名和密码。

    ### 提示

    您的 Gmail 凭据将以明文形式存储在 `server.xml` 文件中。除非您的服务器得到了适当的安全保护，否则不建议这样做。

    ![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_13.jpg)

1.  点击 **保存**。

1.  构建您的作业，确保它成功。

1.  登录 Gmail。访问 **日历** 页面。您现在会看到构建成功已经发布，如下面的截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_14.jpg)

## 工作原理...

通过在 Google 中创建日历，并仅使用三个配置设置，您已将选定的 Jenkins 作业暴露给了 Google 日历。使用相同数量的配置，您可以将大多数现代智能手机和平板电脑连接到日历。

### 注意

Jenkins 有一个凭据管理器，您可以在 `http://localhost:8080/credential-store/` 找到它。凭据管理器可以与许多插件一起使用；然而，在撰写本文时，与 Google 日历插件不兼容。获取最新的兼容性信息，请访问：[`wiki.jenkins-ci.org/display/JENKINS/Credentials+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Credentials+Plugin)

## 还有更多...

在 Jenkins 工作空间中的插件目录下，您将找到一个用于 Google 插件配置帮助的 HTML 文件 `/plugins/gcal/help-projectConfig.html`

用以下内容替换原文：

```
<div>
<p>
Add your local comments here:
</p>
</div>
```

重新启动 Jenkins 服务器后，访问插件配置 `/configure`。您现在会看到新内容，如下面的截图所示：

![还有更多...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_15.jpg)

此示例是一种反模式。如果您需要根据本地需求更改内容，那么最好与社区合作，在 Jenkins SCM 中添加内容，以便每个人都能看到并改进。

您将立即收到通知，您的内容尚未国际化。它需要翻译成 Jenkins 原生支持的语言。幸运的是，在每个 Jenkins 页面的底部，都有一个链接，志愿者可以使用它来上传翻译。翻译需要很少的启动工作量，并且是开始参与开源项目的简单方式。

### 注意

有关如何在 Jenkins 中使用属性文件进行国际化的更多开发详细信息，请阅读 [`wiki.jenkins-ci.org/display/JENKINS/Internationalization`](https://wiki.jenkins-ci.org/display/JENKINS/Internationalization)。

## 另请参阅

+   *Android 和 iOS 的移动应用程序* 教程

# Android 和 iOS 的移动应用程序

有许多用于通知 Jenkins 作业状态的丰富移动应用程序。本教程指向它们的主页，以便您可以选择您喜欢的。

## 准备就绪

您将需要一个可以从互联网访问的 Jenkins 实例或使用 [`ci.jenkins-ci.org/`](http://ci.jenkins-ci.org/)，这是最佳实践的一个很好的例子。我们还假设您有一个移动设备。

## 如何做...

1.  作为管理员，访问**配置系统**（`/configure`）屏幕。

1.  检查 Jenkins URL；如果指向 `localhost`，请更改为使您的服务器链接能够从互联网访问。

1.  访问以下应用程序页面，如果兼容，安装并使用：

    +   **JenkinsMobi** ([`www.jenkins-ci.mobi`](http://www.jenkins-ci.mobi))

    +   **Blamer** ([`www.androidzoom.com/android_applications/tools/blamer_bavqz.html`](http://www.androidzoom.com/android_applications/tools/blamer_bavqz.html) 和 [`github.com/mhussain/Blamer`](https://github.com/mhussain/Blamer))

    +   **Jenkins 心情小部件** ([`wiki.jenkins-ci.org/display/JENKINS/Jenkins+Mood+monitoring+widget+for+Android`](https://wiki.jenkins-ci.org/display/JENKINS/Jenkins+Mood+monitoring+widget+for+Android))

    +   **Jenkins 移动监控** ([`www.androidzoom.com/android_applications/tools/jenkins-mobile-monitor_bmibm.html`](http://www.androidzoom.com/android_applications/tools/jenkins-mobile-monitor_bmibm.html))

    +   **Hudson Helper** ([`wiki.hudson-ci.org/display/HUDSON/Hudson+Helper+iPhone+and+iPod+Touch+App`](http://wiki.hudson-ci.org/display/HUDSON/Hudson+Helper+iPhone+and+iPod+Touch+App))

    +   **Hudson2Go Lite** ([`www.androidzoom.com/android_applications/tools/hudson2go-lite_nane.html`](http://www.androidzoom.com/android_applications/tools/hudson2go-lite_nane.html))

1.  在您的移动设备上，搜索 Google Marketplace 或 iTunes 并安装任何新的 Jenkins 应用程序，这些应用程序是免费的并具有积极的用户推荐。

## 它是如何工作的...

大多数应用程序使用 Jenkins 的 RSS 源（例如 `/rssLatest` 和 `/rssFailed`）获取信息，然后通过移动 Web 浏览器加载链接的页面。除非 Jenkins URL 配置正确，否则链接将断开，您的浏览器将返回`404` `页面未找到`错误。

您很快会注意到，您的应用程序刷新率可能会产生过多的通知，与接收及时信息之间存在微妙的平衡。

**JenkinsMobi** 应用可以在 Android 和 iOS 操作系统上运行。它使用 XML 的远程 API 来收集数据 ([`www.slideshare.net/lucamilanesio/jenkinsmobi-jenkins-xml-api-for-mobile-applications`](http://www.slideshare.net/lucamilanesio/jenkinsmobi-jenkins-xml-api-for-mobile-applications))，而不是更原始的 RSS 订阅。这个选择使得应用的作者能够添加各种功能，使其成为收藏中最引人注目的应用之一。

## 还有更多...

这里还有一些需要考虑的事情。

### Android 1.6 和 Hudson 应用

Jenkins 由于关于 Hudson 名称的商标问题而从 Hudson 的源代码中分离出来 ([`en.wikipedia.org/wiki/Jenkins_%28software%29`](http://en.wikipedia.org/wiki/Jenkins_%28software%29))。大多数开发者转向了与 Jenkins 的合作。这导致了很多第三方 Hudson 代码要么得不到支持，要么被重新命名为 Jenkins。然而，Hudson 和 Jenkins 有很大的共同基础，包括 RSS 订阅的内容。这些细节可能随着时间的推移而有所不同。对于较旧版本的 Android，如 Android 1.6，在 Google Marketplace 中你不会看到任何 Jenkins 应用。可以尝试寻找 Hudson 应用。它们大多在 Jenkins 上运行。

### Virtualbox 和 Android x86 项目

有多种选择可以运行 Android 应用。最简单的方法是通过 Google Marketplace 下载到移动设备上。然而，如果你想在 PC 上通过模拟器来玩耍 Android 应用，可以考虑下载 Android SDK ([`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html))，并使用模拟器和像 `adb` 这样的工具 ([`developer.android.com/guide/developing/tools/adb.html`](http://developer.android.com/guide/developing/tools/adb.html)) 来上传和安装应用。

你也可以通过 VirtualBox、VMware Player 等虚拟机运行一个 x86 映像 ([`www.android-x86.org`](http://www.android-x86.org))。这种方法的一个显著优势是 Android OS 的原始速度，以及保存虚拟机在特定状态下的能力。然而，你不会总是得到预安装的 Google Marketplace。你要么自己找到特定应用的 `.apk` 文件，要么添加其他的市场，比如 **Slide me** ([`m.slideme.org`](http://m.slideme.org))。不幸的是，第二市场提供的选择要少得多。

![Virtualbox 和 Android x86 项目](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_16.jpg)

Windows Android 模拟器 [`bluestacks.com/home.html`](http://bluestacks.com/home.html) 展示了很大的潜力。它不仅是一个模拟器，还提供了一个云服务，可将应用程序从您的移动设备移入和移出模拟器。这承诺是一种高效的开发方法。然而，如果您选择使用此模拟器，请务必彻底审查您在安装时同意的许可证。BlueStacks 希望获取关于您的系统的详细信息，以帮助改进其产品。

## 参见

+   使用 Google 日历进行移动演示的食谱

# 通过 Google Analytics 了解您的受众

如果您有将构建历史或其他信息（例如主页）推送到公共位置的策略，那么您将希望了解查看者的习惯。一种方法是使用 Google Analytics。通过 Google，您可以实时观察访问者访问您的网站。详细的报告提到了流量的整体量、浏览器类型（例如，如果移动应用程序正在访问您的网站）、入口点和国家来源等内容。当您的产品达到路线图的关键点并且您希望了解客户兴趣时，这是特别有用的。

在此食谱中，您将创建一个 Google Analytics 帐户并在 Jenkins 中配置跟踪。然后，您将实时观看流量。

## 准备工作

安装 Google Analytics 插件 ([`wiki.jenkins-ci.org/display/JENKINS/Google+Analytics+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Google+Analytics+Plugin))。

### 提示

如果您不是 Jenkins URL 的所有者，请在创建 Google Analytics 档案之前先征得许可。

## 如何操作...

1.  使用您的 Gmail 帐户登录 Google Analytics ([`www.google.com/analytics/`](http://www.google.com/analytics/))。

1.  填写**创建新帐户**页面的详细信息：

    +   **账户名称**：我的 Jenkins 服务器

    +   **网站名称**：Jenkins 服务器 X

    +   **网站 URL**：与 Jenkins `/configure` 屏幕中的 Jenkins URL 相同。

    +   **报告时区**：输入正确的值

    +   选择**数据共享设置** | **共享设置** | **不共享我的 Google Analytics 数据**

    +   点击**获取跟踪 ID**

    +   点击**接受**以接受**Google Analytics 服务条款**

1.  点击**创建帐户**。

1.  您现在位于新创建的档案的 **帐户** 页面。复制 **TrackingID**，类似于 `UA-121212121212121-1`。

1.  打开第二个浏览器，并以管理员身份登录 Jenkins。

1.  在 **Jenkins 配置系统** 屏幕 (`/configure`) 中，添加从 Google Analytics **Web Property ID** 复制的 **Profile ID**，并将 **Domain Name** 设置为您的 Jenkins URL。

1.  点击**保存**按钮。

1.  访问 Jenkins 的首页以触发跟踪。

1.  返回 Google Analytics，您应该仍然在 **跟踪代码** 选项卡上。点击页面底部的 **保存**。现在，您将看到警告 **跟踪未安装** 已消失。

## 工作原理...

该插件在每个 Jenkins 页面上都添加了一个 JavaScript 页面跟踪器，其中包括域和配置文件 ID。JavaScript 是通过从 Google Analytics 主机中获取并保持更新的，如下所示的代码所示：

```
<script type="text/javascript">
var _gaq = _gaq || [];
_gaq.push(['_setAccount', ' UA-121212121212121-1']);
_gaq.push(['_setDomainName', 'Domain Name']);
_gaq.push(['_trackPageview']);

(function() {
  varga = document.createElement('script'); 
  ga.type = 'text/javascript'; ga.async = true;
  ga.src = ('https:' == document.location.protocol ? 'https://ssl' : 'http://www') + '.google-analytics.com/ga.js';
  var s = document.getElementsByTagName('script')[0]; 
  s.parentNode.insertBefore(ga, s);
})();
</script>
```

Google Analytics 有能力彻底深入了解您的网络使用情况。考虑浏览 Jenkins 并查看通过实时报告功能生成的流量。

### 注意

Google 定期更新其分析服务。如果您注意到任何更改，则分析的帮助页面将记录这些更改（[`support.google.com/analytics`](https://support.google.com/analytics)）。

## 还有更多...

Google Analytics 的开源版本是 Piwik（[`piwik.org/`](http://piwik.org/)）。您可以在本地设置服务器并使用等效的 Jenkins 插件（[`wiki.jenkins-ci.org/display/JENKINS/Piwik+Analytics+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Piwik+Analytics+Plugin)）来生成统计信息。这样做的好处是可以将您的本地数据使用保持在您的控制之下。

顾名思义，Piwik 插件是一个页面装饰器，以与 Google Analytics 插件类似的方式注入 JavaScript。

## 另请参阅

+   *生成首页* 示例

# 使用 R 插件简化强大的可视化效果

R 是一种流行的统计编程语言 [`en.wikipedia.org/wiki/R_(programming_language)`](http://en.wikipedia.org/wiki/R_(programming_language))。它有许多扩展，并具有强大的图形功能。在本示例中，我们将向您展示如何在 Jenkins 任务中使用 R 的图形功能，然后指向一些优秀的入门资源。

### 注意

要查看可改善 Jenkins UI 的插件的完整列表，包括 Jenkins 的图形功能，请访问 [`wiki.jenkins-ci.org/display/JENKINS/Plugins#Plugins-UIplugins`](https://wiki.jenkins-ci.org/display/JENKINS/Plugins#Plugins-UIplugins)。

## 准备工作

安装 R 插件（[`wiki.jenkins-ci.org/display/JENKINS/R+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/R+Plugin)）。查看 R 安装文档（[`cran.r-project.org/doc/manuals/r-release/R-admin.html`](http://cran.r-project.org/doc/manuals/r-release/R-admin.html)）。

## 如何做...

1.  从命令行安装 R 语言：

    ```
    sudo apt-get install r-base

    ```

1.  查看可用的 R 包：

    ```
    apt-cache search r-cran | less

    ```

1.  创建一个名为 `ch4.powerfull.visualizations` 的自由式任务。

1.  在 **构建** 部分，在 **添加构建步骤** 下选择 **执行 R 脚本**。

1.  在 **脚本** 文本区域添加以下代码：

    ```
    paste('=======================================');
    paste('WORKSPACE: ', Sys.getenv('WORKSPACE'))
    paste('BUILD_URL: ', Sys.getenv('BUILD_URL'))
    print('ls /var/lib/jenkins/jobs/R-ME/builds/')
    paste('BUILD_NUMBER: ', Sys.getenv('BUILD_NUMBER'))
    paste('JOB_NAME: ', Sys.getenv('JOB_NAME'))
    paste('JENKINS_HOME: ', Sys.getenv('JENKINS_HOME'))
    paste( 'JOB LOCATION: ', Sys.getenv('JENKINS_HOME'),'/jobs/',Sys.getenv('JOB_NAME'),'/builds/', Sys.getenv('BUILD_NUMBER'),"/test.pdf",sep="")
    paste('=======================================');

    filename<-paste('pie_',Sys.getenv('BUILD_NUMBER'),'.pdf',sep="")
    pdf(file=filename)
    slices<- c(1,2,3,3,6,2,2)
    labels <- c("Monday", "Tuesday", "Wednesday", "Thursday", "Friday","Saturday","Sunday")
    pie(slices, labels = labels, main="Number of failed jobs for each day of the week")

    filename<-paste('freq_',Sys.getenv('BUILD_NUMBER'),'.pdf',sep="")
    pdf(file=filename)
    Number_OF_LINES_OF_ACTIVE_CODE=rnorm(10000, mean=200, sd=50)
    hist(Number_OF_LINES_OF_ACTIVE_CODE,main="Frequency plot of Class Sizes")

    filename<-paste('scatter_',Sys.getenv('BUILD_NUMBER'),'.pdf',sep="")
    pdf(file=filename)
    Y <- rnorm(3000)
    plot(Y,main='Random Data within a normal distribution')
    ```

1.  点击 **保存** 按钮。

1.  点击 **立即构建** 图标。

1.  在 **构建历史** 下，点击 **工作空间** 按钮。

1.  通过单击链接 **freq_1.pdf**、**pie_1.pdf** 和 **scatter_1.pdf** 来查看生成的图形，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_17.jpg)

以下截图是由 R 脚本在构建过程中生成的随机数据的值的直方图。该数据模拟了大型项目中的班级规模。

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_18.jpg)

另一个视图是饼图。伪数据表示一周中每天失败任务的数量。如果你将其与你自己的值绘制在一起，可能会看到特别糟糕的日子，比如周末前后的日子。这可能会影响开发人员的工作方式，或者周内的动力分配。

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_19.jpg)

执行以下步骤：

1.  运行任务并查看 **工作区**。

1.  点击 **控制台输出**。你会看到类似于以下内容的输出：

    ```
    Started by user anonymous
    Building in workspace /var/lib/jenkins/workspace/ch4.Powerfull.Visualizations
    [ch4.Powerfull.Visualizations] $ Rscript /tmp/hudson6203634518082768146.R
    [1] "======================================="
    [1] "WORKSPACE:  /var/lib/jenkins/workspace/ch4.Powerfull.Visualizations"
    [1] "BUILD_URL:  "
    [1] "ls /var/lib/jenkins/jobs/R-ME/builds/"
    [1] "BUILD_NUMBER:  9"
    [1] "JOB_NAME:  ch4.Powerfull.Visualizations"
    [1] "JENKINS_HOME:  /var/lib/jenkins"
    [1] "JOB LOCATION: /var/lib/jenkins/jobs/ch4.Powerfull.Visualizations/builds/9/test.pdf"
    [1] "======================================="
    Finished: SUCCESS

    ```

1.  点击 **返回项目**。

1.  点击 **工作区**。

## 工作原理...

用几行 R 代码，你就生成了三个不同的、精美的 PDF 图表。

R 插件在构建过程中运行了一个脚本。该脚本将 `WORKSPACE` 和其他 Jenkins 环境变量打印到控制台上：

```
paste ('WORKSPACE: ', Sys.getenv('WORKSPACE'))
```

然后，文件名以附加到字符串 `pie_` 的构建号设置。这样可以使脚本每次运行时生成不同的文件名，如下所示：

```
filename <-paste('pie_',Sys.getenv('BUILD_NUMBER'),'.pdf',sep="")
```

脚本现在通过命令 `pdf(file=filename)` 打开输出到 `filename` 变量中定义的位置。默认情况下，输出目录是任务的工作区。

接下来，我们为图表定义了伪数据，表示一周中任意一天失败任务的数量。注意，在模拟世界中，星期五是一个糟糕的日子：

```
slices <- c(1,2,3,3,6,2,2)
labels <- c("Monday", "Tuesday", "Wednesday", "Thursday", "Friday","Saturday","Sunday")
```

绘制饼图：

```
pie(slices, labels = labels, main="Number of failed jobs for each day of the week")
```

对于第二个图表，我们在正态分布内生成了 10,000 个随机数据。伪数据表示运行给定作业的活动代码行数，如下所示：

```
Number_OF_LINES_OF_ACTIVE_CODE=rnorm(10000, mean=200, sd=50)
```

`hist` 命令生成频率图：

```
hist(Number_OF_LINES_OF_ACTIVE_CODE,main="Frequency plot of Class Sizes")
```

第三个图表是一个散点图，包含在正态分布内随机生成的 3,000 个数据点。这代表了一个典型的抽样过程，比如使用 Sonar 或 FindBugs 找到的潜在缺陷数量，如下所示：

```
Y <- rnorm(3000)
plot(Y,main='Random Data within a normal distribution')
```

我们将把将真实数据与 R 的绘图功能链接起来的工作留给读者作为练习。

## 更多内容...

这里还有几点让你思考。

### RStudio 或 StatET

用于 R 的一个流行的 IDE 是 **RStudio**（[`www.rstudio.com/`](http://www.rstudio.com/)）。开源版本是免费的。功能集包括带有代码完成和语法高亮的源代码编辑器、集成帮助、可靠的调试功能以及一系列其他功能，如下面的截图所示：

![RStudio 或 StatET](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_04_20.jpg)

Eclipse 环境的另一种选择是 StatET 插件（[`www.walware.de/goto/statet`](http://www.walware.de/goto/statet)）。

### 快速获取帮助

学习 R 的第一步是从 R 控制台输入 `help.start()`。该命令会启动一个带有主要文档概述的浏览器。

如果你想要 R 命令的描述，那么在命令前输入 `?` 将生成详细的帮助文档。例如，在我们查看 `rnorm` 命令的配方时。键入 `?rnorm` 将产生类似的文档：

**正态分布**

**描述**

**用平均值等于 mean 和标准差等于 sd 的正态分布的密度、分布函数、分位数函数和随机生成。**

**使用方法**

**dnorm(x, mean = 0, sd = 1, log = FALSE)**

**pnorm(q, mean = 0, sd = 1, lower.tail = TRUE, log.p = FALSE)**

**qnorm(p, mean = 0, sd = 1, lower.tail = TRUE, log.p = FALSE)**

**rnorm(n, mean = 0, sd = 1)**

### 了解更多信息

R 语言有很好的文档。以下是一些有用的资源：

+   **Data Camp** ([`www.datacamp.com/courses`](https://www.datacamp.com/courses))：这是一个包括基本介绍和更详细的统计课程的免费在线课程的绝佳集合。

+   **为其他语言用户准备的 R 编程** ([`www.johndcook.com/blog/r_language_for_programmers/`](http://www.johndcook.com/blog/r_language_for_programmers/))：这是一个快速介绍，针对具有其他语言经验的新程序员可能遇到的问题。

+   **Google 的 R 风格指南** ([`google-styleguide.googlecode.com/svn/trunk/Rguide.xml`](https://google-styleguide.googlecode.com/svn/trunk/Rguide.xml))：如果你遵循这些指南，你的代码将保持一致且易读。

+   **MOOCs**：Edx、Coursera 等网站提供了许多在线课程。值得浏览它们的课程列表以寻找相关课程。要获取最新的 Coursera 课程列表，请访问 [`www.coursera.org/courses`](https://www.coursera.org/courses)。

+   **两分钟教程** ([`www.twotorials.com/`](http://www.twotorials.com/))：这里包含许多在 R 中可以做的事情的两分钟 YouTube 示例。

+   **R 的 Wiki 书籍** ([`en.wikibooks.org/wiki/Category:R_Programming`](http://en.wikibooks.org/wiki/Category:R_Programming))：这里汇集了许多优秀的文章和示例。

## 另请参阅

+   在 第五章 的 *使用指标来提高质量* 中的 *使用 R 插件分析项目数据* 配方
