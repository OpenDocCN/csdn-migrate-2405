# 使用安卓片段创建动态 UI（一）

> 原文：[`zh.annas-archive.org/md5/483E44769E1E47CD0C380E136A5A54D5`](https://zh.annas-archive.org/md5/483E44769E1E47CD0C380E136A5A54D5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

移动应用静态用户界面挤在微小屏幕上的日子已经一去不复返了。如今，用户期望移动应用是动态且高度交互的。他们希望在中分辨率智能手机上查看应用时看起来很棒，而且在使用高分辨率平板电脑时，同样的应用看起来也应该非常出色。应用需要提供丰富的导航功能。同时，应用需要具备适应性和响应性。

试图使用 Android 传统的以活动为中心的用户界面设计模型来满足这些需求是困难的。作为开发者，我们需要比活动所提供的更多的控制。我们需要一种新的方法：片段为我们提供了这种方法。

在这本书中，你将学习如何使用片段来满足在现代移动应用开发中创建动态用户界面的挑战。

# 本书涵盖的内容

第一章, *片段与用户界面模块化*, 介绍了片段、用户界面模块化以及片段在开发模块化用户界面中扮演的角色。本章演示了简单片段的创建以及在活动中静态使用片段。

第二章, *片段与用户界面的灵活性*, 在前一章引入的概念基础上，提供了针对设备布局特定差异的解决方案。本章说明了如何使用自适应活动布局定义，以支持各种设备形态，通过一组小片段自动根据当前设备的用户界面需求重新排列。

第三章, *片段的生命周期和专门化*, 讨论了片段的生命周期与活动生命周期的关系，并在生命周期的各个阶段展示了适当的编程操作。利用这一知识，引入了专门用途的片段类`ListFragment`和`DialogFragment`，以展示它们的行为，并提供对它们在活动生命周期中的行为与标准片段不同的更深入了解。

第四章, *使用片段事务*, 解释了如何通过动态地添加和移除片段来在单个活动中创建多个应用屏幕。涵盖的主题包括实现返回按钮行为以及动态地适应多片段用户界面到设备特性的差异。

第五章，*创建丰富的片段导航*，通过在前几章的基础上构建，将一切内容整合在一起，展示如何使用片段通过丰富的导航功能来增强用户体验。这一章演示了如何实现包括基于滑动翻页的屏幕浏览、带有下拉列表导航的直接屏幕访问以及通过标签随机查看屏幕等多种导航功能。

# 阅读本书所需的准备

要跟随本书中的示例，你应该具备基本的 Android 编程知识和一个可用的 Android 开发环境。

本书主要关注以 Android Studio 作为 Android 开发环境，但也可以使用其他工具，如带有 ADT 插件的 Eclipse、JetBrains 的 IntelliJ IDEA 或类似的 Android 支持开发工具。

# 本书适合的读者

本书适合任何具备基本 Android 编程理解的人，他们希望改善应用程序的外观和可用性。

无论你是希望创建更具交互性的用户体验、创建更动态自适应的 UI、为平板电脑和智能手机提供更好的单一应用支持、减少管理应用 UI 的复杂性，还是仅仅尝试扩展你的 UI 设计理念，这本书都是为你而写的。

# 约定

在这本书中，你会发现多种文本样式，用于区分不同类型的信息。以下是一些样式示例，以及它们的含义解释。

文本中的代码字如下显示："一个应用程序最初调用`startActivity`方法来显示`Activity1`的实例。`Activity1`。"

代码块如下设置：

```java
<string-array name="screen_names">
  <item>First View</item>
  <item>Second View</item>
  <item>Third View</item>
</string-array>
```

**新术语**和**重要词汇**会以粗体显示。你在屏幕上看到的词，比如菜单或对话框中的，会在文本中以这样的形式出现："选择**布局**作为**资源类型**。"

### 注意

警告或重要说明会以这样的框显示。

### 提示

提示和技巧会像这样出现。

# 读者反馈

我们始终欢迎读者的反馈。告诉我们你对这本书的看法——你喜欢或可能不喜欢的内容。读者的反馈对我们来说很重要，它能帮助我们开发出对你真正有用的标题。

要给我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在邮件的主题中提及书名。

如果你在一个主题上有专业知识，并且有兴趣撰写或参与书籍编写，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)的作者指南。

# 客户支持

既然你现在拥有了 Packt 的一本书，我们有一些事情可以帮助你最大限度地利用你的购买。

## 下载示例代码

你可以从你在[`www.packtpub.com`](http://www.packtpub.com)的账户下载你所购买的所有 Packt 书籍的示例代码文件。如果你在其他地方购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会直接将文件通过电子邮件发送给你。

## 勘误

尽管我们已经竭尽全力确保内容的准确性，但错误仍然在所难免。如果你在我们的书中发现了一个错误——可能是文本或代码中的错误——我们非常感激你能向我们报告。这样做可以避免其他读者产生困扰，并帮助我们改进本书后续版本。如果你发现任何勘误信息，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择你的书籍，点击**勘误提交表单**链接，并输入你的勘误详情。一旦你的勘误信息被核实，你的提交将被接受，并且勘误信息将被上传到我们的网站，或添加到该书勘误部分现有的勘误列表中。任何现有的勘误信息可以通过在[`www.packtpub.com/support`](http://www.packtpub.com/support)选择你的标题来查看。

## 盗版

在互联网上对版权材料的盗版是一个所有媒体都面临的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果你在互联网上以任何形式遇到我们作品的非法副本，请立即提供我们该位置地址或网站名称，以便我们可以寻求补救措施。

如果有疑似盗版材料，请通过`<copyright@packtpub.com>`联系我们，并提供一个链接。

我们感谢你帮助保护我们的作者，以及我们为你提供有价值内容的能力。

## 问题

如果你对书籍的任何方面有问题，可以联系`<questions@packtpub.com>`，我们将尽力解决。


# 第一章：碎片和用户界面模块化

本章将介绍碎片、用户界面模块化以及碎片在开发模块化用户界面中所扮演的角色。本章将演示如何创建简单的碎片，并在活动中静态使用碎片。

让我们看看将要讨论的主题：

+   对用户界面模块化的需求

+   碎片是模块化的基础

+   对跨 Android 版本的碎片支持

+   创建碎片

到本章结束时，我们将能够在静态活动布局中创建和使用碎片。

# 对 UI 创建新方法的需求

你成为 Android 开发者后，可能学的第一个类就是`Activity`类。毕竟，`Activity`类为你的应用程序提供了用户界面。通过将用户界面组件组织到活动中，活动就成为了你绘制应用程序杰作的地方。

在 Android 早期，直接在活动中构建应用程序的用户界面还是相当可行的。早期的多数应用程序用户界面相对简单，而且不同的 Android 设备形态也较少。在大多数情况下，借助一些布局资源，单个活动就能很好地适应不同的设备形态。

现在，Android 设备具有各种各样的形态，其尺寸和形状的差异性令人惊叹。结合现代 Android 应用程序丰富的、高度交互的用户界面，创建一个能够有效管理跨如此多样形态因子的用户界面的单一活动变得极其困难。

一个可能的解决方案是定义一个活动，以为一部分设备形态因子提供用户体验，例如智能手机。然后再为另一部分形态因子，如平板电脑，定义另一个活动。这种做法的问题是，活动往往需要负责很多除了渲染用户界面之外的任务。当多个活动实质上执行相同的任务时，我们必须在每个活动中复制逻辑，或者通过找到在活动间共享逻辑的方法来增加程序的复杂性。为不同形态因子使用不同活动的方法也会大大增加程序中的活动数量，容易将所需的活动数量翻倍甚至三倍。

我们需要更好的解决方案。我们需要一个能够将应用程序用户界面模块化为可以在活动中按需排列的区域的解决方案。碎片就是这样的解决方案。

Android 碎片允许我们将用户界面划分为功能性用户界面组件和逻辑的分组。活动可以根据给定的设备形态因子按需加载和排列碎片。碎片负责处理形态因子的细节，而活动则管理整体的用户界面问题。

## 片段的广泛平台支持

`Fragment`类在 API 级别 11（Android 3.0）时被添加到 Android 中。这是第一个正式支持平板电脑的 Android 版本。平板电脑支持的增加加剧了一个已经困难的问题；由于 Android 设备形态因素的多样性，开发 Android 应用程序变得越来越困难。

幸运的是，片段为我们提供了一个解决问题的方案。通过片段，我们可以更容易地创建支持各种形态因素的应用程序，因为我们能够将用户界面划分为有效的组件组合及其相关的逻辑。

片段有一个问题。直到最近，大多数 Android 设备的 API 级别都在 11 以下，因此不支持片段。幸运的是，谷歌发布了 Android 支持库，可以在[`developer.android.com/tools/extras/support-library.html`](http://developer.android.com/tools/extras/support-library.html)获取，这使得任何运行 API 级别 4（Android 1.6）或更高版本的设备都能使用片段。通过 Android 支持库，片段现在几乎可以在所有正在使用的 Android 设备上使用。

### 注意

使用 Android Studio 创建的应用程序会自动包含 Android 支持库，因此几乎在所有使用的 SDK 版本上都支持片段。如果你将使用除 Android Studio 以外的开发工具来创建针对运行在 SDK 级别 11 以下设备的应用程序，请访问[`android-developers.blogspot.com/2011/03/fragments-for-all.html`](http://android-developers.blogspot.com/2011/03/fragments-for-all.html)，查看 Android 开发者博客文章《*Fragments For All*》，了解如何手动将 Android 支持库添加到你的项目中。

## 片段简化了常见的 Android 任务

片段不仅简化了我们创建应用程序用户界面的方式，还简化了许多内置的 Android 用户界面任务。诸如标签显示、列表显示和对话框等用户界面概念，在历史上都有明显不同的处理方法。然而，当我们深入思考时，它们实际上都是将用户界面组件和逻辑组合成一个功能组的共同概念的变体。片段正式化了这一概念，因此允许我们以前对这些不同的任务采取一致的处理方法。我们将在本书后面详细讨论这些问题以及一些专门的片段类，如`DialogFragment`类和`ListFragment`类。

## 片段与活动之间的关系

片段并不替代活动，而是对其进行补充。一个片段总是存在于一个活动中。一个活动实例可以包含任意数量的片段，但给定的片段实例只能存在于一个单一活动中。一个片段与其所在的活动紧密相关，该片段的生命周期与其包含活动的生命周期紧密耦合。我们将在第三章，*片段生命周期和专业化*中更多地讨论片段的生命周期与其包含活动的紧密关系。

我们不想犯的一个常见错误是过度使用片段。通常当有人了解到片段时，他们会假设每个活动都必须包含片段，但这并非总是如此。

在阅读本书的过程中，我们将讨论片段的功能和特性以及它们在各种场景中的优势。在构建应用程序时，我们始终要牢记这些。在片段能增加价值的情况下，我们当然希望使用它们。然而，同样重要的是，我们应避免在片段不能提供价值的情况下使用片段，以免使应用程序复杂化。

# 转向使用片段

尽管片段是一个非常强大的工具，但它们本质上做的事情非常简单。片段将用户界面组件及其相关逻辑分组。为与片段相关的用户界面创建部分与为活动创建非常相似。在大多数情况下，特定片段的视图层次结构是从一个布局资源创建的；尽管如此，与活动一样，视图层次结构也可以编程生成。

为片段创建布局资源遵循与为活动创建相同的规则和技术。关键的区别在于，在使用片段时，我们正在寻找将用户界面布局划分为可管理的子部分的机会。

我们通过将传统的以活动为中心的用户界面转换为使用片段来开始使用片段是最简单的方法。

## 旧的思维方式——以活动为中心

首先，让我们看看我们要转换的应用程序的外观和结构。这个应用程序包含一个单一活动，运行时看起来如下截图所示：

![旧的思维方式——以活动为中心](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_01_01_NEW.jpg)

活动在活动顶部显示五个书名的列表。当用户选择这些书名中的一个时，所选书籍的描述将出现在活动的底部。

### 定义活动的外观

活动的显示外观在名为`activity_main.xml`的布局资源文件中定义，该文件包含以下布局描述：

```java
<LinearLayout

    android:orientation="vertical"
    android:layout_width="match_parent"
    android:layout_height="match_parent">

  <!-- List of Book Titles -->
  <ScrollView
      android:layout_width="match_parent"
      android:layout_height="0dp"
      android:id="@+id/scrollTitles"
      android:layout_weight="1">
    <RadioGroup
        android:id="@+id/bookSelectGroup"
        android:layout_height="wrap_content"
        android:layout_width="wrap_content"
    >
      <RadioButton
          android:id="@+id/dynamicUiBook"
          android:layout_height="wrap_content"
          android:layout_width="wrap_content"
          android:text="@string/dynamicUiTitle"
          android:checked="true" />
      <RadioButton
          android:id="@+id/android4NewBook"
          android:layout_height="wrap_content"
          android:layout_width="wrap_content"
          android:text="@string/android4NewTitle" />

      <!-- Other RadioButtons elided for clarify -->

    </RadioGroup>
  </ScrollView>

  <!-- Description of selected book -->
  <ScrollView
      android:layout_width="match_parent"
      android:layout_height="0dp"
      android:id="@+id/scrollDescription"
      android:layout_weight="1">

    <TextView
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:textAppearance="?android:attr/textAppearanceMedium"
        android:text="@string/dynamicUiDescription"
        android:id="@+id/textView"
        android:paddingLeft="@dimen/activity_horizontal_margin"
        android:paddingRight="@dimen/activity_horizontal_margin"
        android:gravity="fill_horizontal"/>
  </ScrollView>
</LinearLayout>
```

### 提示

**下载示例代码**

您可以从您的账户 [`www.packtpub.com`](http://www.packtpub.com) 下载您购买的所有 Packt 书籍的示例代码文件。如果您在别处购买了这本书，可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 注册，我们会将文件直接通过电子邮件发送给您。

这个布局资源相对简单，以下是其解释：

+   整体布局是在一个垂直方向的 `LinearLayout` 元素中定义的，其中包含两个 `ScrollView` 元素。

+   两个 `ScrollView` 元素都有一个 `layout_weight` 值为 `1`，这使得顶级 `LinearLayout` 元素能够在两个 `ScrollView` 元素之间平均分配屏幕。

+   顶部的 `ScrollView` 元素，其 `id` 值为 `scrollTitles`，包装了一个包含一系列 `RadioButton` 元素的 `RadioGroup` 元素，每个书籍对应一个。

+   底部的 `ScrollView` 元素，其 `id` 值为 `scrollDescription`，包含一个 `TextView` 元素，用于显示所选书籍的描述

### 显示活动用户界面

应用程序的活动类 `MainActivity` 直接继承自 `android.app.Activity` 类。为了显示活动的用户界面，我们重写 `onCreate` 方法并调用 `setContentView` 方法，传递 `R.layout.activity_main` 布局资源 ID。

```java
public class MainActivity extends Activity {

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    // load the activity_main layout resource
    setContentView(R.layout.activity_main);
  }

  // Other methods elided for clarity
}
```

## 新的思考方式——面向片段

我们目前的活动导向型用户界面在所有 Android 设备具有相同形态因数的情况下是没问题的。正如我们所讨论的，情况并非如此。

我们需要将应用程序用户界面进行分区，这样我们就可以转向面向片段的方法。通过适当的分区，我们可以准备对我们的应用程序进行一些简单的增强，以帮助它适应设备差异。

让我们看看我们可以进行的一些简单更改，这些更改会将我们的用户界面分区。

### 创建片段布局资源

向面向片段的用户界面转变的第一步是识别现有用户界面中的自然分区。在这个应用程序的案例中，自然分区相对容易识别。书名列表是一个很好的候选者，书籍描述是另一个。我们将它们各自做成一个独立的片段。

#### 将布局定义为可重用的列表

对于书名列表，我们可以选择定义一个包含最靠近顶部的 `ScrollView` 元素（其 `id` 值为 `scrollTitles`）的片段，或者只包含该 `ScrollView` 元素内的 `RadioGroup` 元素。创建片段时，我们希望构建它，以便片段最容易复用。尽管我们只需要 `RadioGroup` 元素来显示标题列表，但似乎我们总是希望用户在必要时能够滚动标题列表。在这种情况下，将 `ScrollView` 元素包含在此片段中是有意义的。

为了创建书籍列表的片段，我们定义了一个名为`fragment_book_list.xml`的新布局资源文件。我们从`activity_main.xml`资源文件中复制顶部的`ScrollView`元素及其内容到`fragment_book_list.xml`资源文件中。结果`fragment_book_list.xml`资源文件如下：

```java
<!-- List of Book Titles -->
<ScrollView
    android:layout_width="match_parent"
    android:layout_height="0dp"
    android:id="@+id/scrollTitles"
    android:layout_weight="1">
  <RadioGroup
      android:id="@+id/bookSelectGroup "
      android:layout_height="wrap_content"
      android:layout_width="wrap_content" >
    <RadioButton
        android:id="@+id/dynamicUiBook"
        android:layout_height="wrap_content"
        android:layout_width="wrap_content"
        android:text="@string/dynamicUiTitle"
        android:checked="true"   />
    <RadioButton
        android:id="@+id/android4NewBook"
        android:layout_height="wrap_content"
        android:layout_width="wrap_content"
        android:text="@string/android4NewTitle"    />

    <!-- Other RadioButtons elided for clarify -->

  </RadioGroup>
</ScrollView>
```

这让我们得到了一个与用户界面中书名部分一致的活动布局资源。这是一个良好的开始。

#### 最小化假设

一个有效的以片段为导向的用户界面是由最小化关于片段如何以及在哪里使用的假设的布局资源构建的。我们对片段使用的假设越少，片段的可重用性就越高。

当前我们在`fragment_book_list.xml`资源文件中的布局非常受限，因为它包含了很多假设。例如，根`ScrollView`元素包含一个`layout_height`属性，其值为`0`。这假设了片段将被放置在计算片段高度的布局中。

当我们使用`layout_height`属性值为`0`的片段时，在需要`ScrollView`元素指定有意义的高度的许多布局中，`ScrollView`元素无法正确渲染。即使将片段放入水平方向的`LinearLayout`元素中这样简单的操作，`layout_height`属性值为`0`也会导致片段无法正确渲染。`layout_weight`属性也存在类似问题。

通常，一个好的实践是设计片段以完全占据其所在的任何空间。这样，使用该片段的布局就能最大程度地控制片段的位置和大小。

为此，我们将从`ScrollView`元素中移除`layout_weight`属性，并将`layout_height`属性值更改为`match_parent`。因为现在`ScrollView`元素是布局资源的根节点，我们还需要添加`android`命名空间前缀声明。

下面的代码片段展示了更新后的`ScrollView`元素：

```java
<ScrollView

    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:id="@+id/scrollTitles">

  <!—RadioGroup and RadioButton elements elided for clarity -->

</ScrollView>
```

使用更新后的`ScrollView`元素，片段布局现在可以适应几乎任何引用它的布局。

#### 封装显示布局

对于书籍描述，我们将定义一个名为`fragment_book_desc.xml`的布局资源文件。片段布局包括活动布局资源底部`ScrollView`元素的内容（其`id`值为`scrollDescription`）。就像在书籍列表片段中一样，我们将移除`layout_weight`属性，将`layout_height`属性设置为`match_parent`，并添加`android`命名空间前缀声明。

`fragment_book_desc.xml`布局资源文件如下所示：

```java
<!-- Description of selected book -->
<ScrollView

    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:id="@+id/scrollDescription">
  <TextView
      android:layout_width="wrap_content"
      android:layout_height="wrap_content"
      android:textAppearance="?android:attr/textAppearanceMedium"
      android:text="@string/dynamicUiDescription"
      android:id="@+id/textView"
      android:paddingLeft="@dimen/activity_horizontal_margin"
      android:paddingRight="@dimen/activity_horizontal_margin"
      android:gravity="fill_horizontal"/>
</ScrollView>
```

### 创建片段类

与创建活动时一样，我们的片段不仅需要简单的布局定义；还需要一个类。

#### 在片段中包装列表

所有片段类必须直接或间接扩展 `android.app.Fragment` 类。

### 注意

对于依赖 Android 支持库为 API 级别 11（Android 3.0）之前的设备提供片段支持的项目，请使用 `android.support.v4.app.Fragment` 类代替 `android.app.Fragment` 类。

我们将管理书籍列表的片段类称为 `BookListFragment`。这个类将直接扩展 `Fragment` 类，如下所示：

```java
Import android.app.Ftragment;
public class BookListFragment extends Fragment { … }
```

在创建片段时，Android 框架会调用片段上的许多方法。其中最重要的方法之一是 `onCreateView`。`onCreateView` 方法负责返回由片段表示的视图层次结构。Android 框架将返回的片段视图层次结构附加到活动的整体视图层次结构中的适当位置。

在像 `BookListFragment` 类这样的情况中，如果 `Fragment` 类直接从 `Fragment` 类继承，我们必须重写 `onCreateView` 方法并执行构造视图层次结构所需的工作。

`onCreateView` 方法接收三个参数。现在我们重点关注前两个：

+   `inflater`：这是对 `LayoutInflater` 实例的引用，它能够在包含活动的上下文中读取和扩展布局资源。

+   `container`：这是对活动布局中 `ViewGroup` 实例的引用，片段的视图层次结构将附加到该位置。

`LayoutInflater` 类提供了一个名为 `inflate` 的方法，该方法处理将布局资源转换为相应的视图层次结构并返回该层次结构的根视图的引用。使用 `LayoutInflater.inflate` 方法，我们可以实现 `BookListFragment` 类的 `onCreateView` 方法，以构造并返回与 `R.layout.fragment_book_list` 布局资源对应的视图层次结构，如下面的代码所示：

```java
@Override
public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
    View viewHierarchy = 
    inflater.inflate(R.layout.fragment_book_list, 
    container, false);
    return viewHierarchy;
}
```

你会注意到在前面的代码中，我们在调用 `inflate` 方法时包含了 `container` 引用和一个布尔值 `false`。`container` 引用为 `inflate` 方法提供了必要的布局参数，以便正确格式化新的视图层次结构。参数值 `false` 表示 `container` 只用于布局参数。如果这个值是 true，`inflate` 方法还会将新的视图层次结构附加到 `container` 视图组。我们不想在 `onCreateView` 方法中将新的视图层次结构附加到 `container` 视图组，因为活动会处理这个问题。

#### 提供显示片段

对于书籍描述片段，我们将定义一个名为 `BookDescFragment` 的类。这个类与 `BookListFragment` 类相同，不同之处在于 `BookDescFragment` 类使用 `R.layout.fragment_book_desc` 布局资源，如下所示：

```java
public class BookDescFragment extends Fragment {
  @Override
  public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
    View viewHierarchy = inflater.inflate(R.layout.fragment_book_desc, container, false);
    return viewHierarchy;
  }
}
```

### 将活动转换为使用片段

定义了片段之后，我们现在可以更新活动以使用它们。首先，我们将从 `activity_main.xml` 布局资源文件中删除所有书籍标题和描述布局信息。现在该文件只包含顶级 `LinearLayout` 元素和注释，以显示书籍标题和描述应该放置的位置，如下所示：

```java
<LinearLayout
    android:orientation="vertical"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    >

  <!--  List of Book Titles  -->

  <!--  Description of selected book  -->

</LinearLayout>
```

使用 `fragment` 元素，我们可以通过引用片段类的类名来将片段添加到布局中，使用 `name` 属性。例如，以下是我们如何引用书籍列表片段类 `BookListFragment`：

```java
<fragment
    android:name="com.jwhh.fragments.BookListFragment"
    android:id="@+id/fragmentTitles"/>
```

我们希望使用片段时，活动的用户界面看起来与转换前一样。为此，我们在片段元素上添加与原始布局中 `ScrollView` 元素相同的 `layout_width`、`layout_height` 和 `layout_weight` 属性值。

这样，活动的完整布局资源文件 `activity_main.xml` 现在如下所示：

```java
<LinearLayout
    android:orientation="vertical"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    >

  <!-- List of Book Titles -->
  <fragment
      android:layout_width="match_parent"
      android:layout_height="0dp"
      android:layout_weight="1"
      android:name="com.jwhh.fragments.BookListFragment"
      android:id="@+id/fragmentTitles"/>

  <!-- Description of selected book -->
  <fragment
      android:layout_width="match_parent"
      android:layout_height="0dp"
      android:layout_weight="1"
      android:name="com.jwhh.fragments.BookDescFragment"
      android:id="@+id/fragmentDescription"/>
</LinearLayout> 
```

### 注意

如果你在使用 Android Studio，你可能会在 `fragment` 元素上发现一个 `tools:layout` 属性。这个属性由 Android Studio 使用，以便在图形设计器中提供布局预览。当应用程序运行时，它对应用程序的外观没有任何影响。

当应用程序运行时，用户界面现在将完全按照在活动中定义时的样子出现。如果我们针对的是运行 API 级别 11（Android 3.0）或更高版本的 Android 设备，那么无需对 `Activity` 类进行任何更改，因为此时 `Activity` 类只是加载并显示布局资源。

#### 活动和向后兼容性

当使用 Android 支持库来提供 API 级别 11（Android 3.0）之前的片段支持时，我们还需要多做一步。在这种情况下，我们必须对活动进行一个小但重要的更改。我们必须将 `MainActivity` 类的基础类从 `Activity` 类更改为 `android.support.v4.app.FragmentActivity` 类。因为 API 级别 11 之前的 `Activity` 类不理解片段，所以我们使用 Android 支持库中的 `FragmentActivity` 类来为 `MainActivity` 类添加片段支持。

# 总结

从以活动为导向的旧思维转向以片段为导向的新思维，为我们的应用程序开启了丰富的可能性。片段使我们能更好地组织用户界面的外观以及用于管理它的代码。借助片段，我们应用程序的用户界面采用了更加模块化的方法，使我们摆脱了特定设备功能的限制，为应对当今丰富多样的设备以及未来可能出现的新设备做好了准备。

在下一章中，我们将基于用片段创建的模块化用户界面继续构建，以使我们的应用程序能够自动适应各种设备形态的差异，而只需对我们的应用程序进行最小的更改。


# 第二章：片段与用户界面的灵活性

本章在上一章的基础上，提供了针对设备布局差异的具体解决方案。本章介绍了如何使用自适应 Activity 布局定义来创建应用，这些应用可以自动根据设备形态差异调整用户界面。通过自适应 Activity 布局定义，应用只需使用少数几个精心设计的片段，就能支持各种类型的设备。

在本章中，我们将涵盖以下主题：

+   简化支持设备差异的挑战

+   动态资源选择

+   协调片段内容

+   `FragmentManager`的角色

+   支持跨活动的片段

到本章结束时，我们将能够实现一个用户界面，它使用片段来自动适应设备布局的差异，并协调涉及片段中的用户操作。

# 创建用户界面的灵活性

在用户界面设计中使用片段为我们创建能够更容易适应设备差异的应用提供了一个良好的基础，但我们还必须更进一步，以创建真正灵活的用户界面。我们必须设计应用程序，使得构成用户界面的片段能够根据应用当前运行的设备的特性轻松重新排列。

为此，我们必须使用一些技术来动态地根据当前设备的特性改变单个片段的布局。一旦我们采用了这种技术，我们必须确保我们实现的每个片段都能在布局变化中有效地独立运作，这些变化可能会影响活动中其他片段的行为甚至存在。

## 动态片段布局选择

如我们在上一节提到的，创建灵活的用户界面需要片段在活动中的布局和定位能够根据设备特性的差异进行改变。我们可以在应用中包含代码，以动态响应设备形态因素来排列片段，但在大多数情况下，这样做不仅不必要，而且也不可取。用户界面与代码之间的依赖关系越深，维护和增强应用程序就越困难。尽管用户界面和应用程序代码之间总会有一定程度的依赖，但我们希望尽可能减少这种依赖，并在布局资源中尽可能完成与用户界面布局相关的所有工作。

使我们的应用程序用户界面具有灵活性的最简单方法是利用 Android 资源系统内置的设备适应性。Android 允许我们为应用程序设计不同的布局相关资源，每种资源都针对一组特定的设备特性进行了优化和关联。在运行时，Android 资源系统会自动选择并加载适合当前设备的适当资源。尽管此功能可用于动态修改任何活动的布局，但我们会发现当与片段结合使用时，它特别有效。

为了看到 Android 资源选择的效果，让我们继续上一章的应用程序。你会记得，我们活动的布局在`activity_main.xml`资源文件中，看起来像这样：

```java
<LinearLayout
    android:orientation=""vertical""
    android:layout_width=""match_parent""
    android:layout_height=""match_parent""
    ">

  <!-- List of Book Titles -->
  <fragment
      android:layout_width=""match_parent""
      android:layout_height=""0dp""
      android:layout_weight=""1""
      android:name=""com.jwhh.fragments.BookListFragment""
      android:id=""@+id/fragmentTitles""/>

  <!-- Description of selected book -->
  <fragment
      android:layout_width=""match_parent""
      android:layout_height=""0dp""
      android:layout_weight=""1""
      android:name=""com.jwhh.fragments.BookDescFragment""
      android:id=""@+id/fragmentDescription""/>
</LinearLayout>
```

这个布局将我们的片段`BookListFragment`和`BookDescFragment`堆叠在一起。尽管这种布局在竖直握持智能手机的肖像方向上渲染良好，但是将手机旋转到水平握持的横屏方向时，会出现像这里一样不太吸引人的外观：

![动态片段布局选择](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_02_01.jpg)

当前布局显然没有充分利用这种方向下的可用屏幕空间。当手机以横屏方向定位时，如果我们将两个片段并排放置，应用程序看起来会更好。

### 添加一个备用布局资源

我们可以通过创建一个适当排列片段的新资源文件，为我们的应用程序添加对备用布局的支持。要创建资源文件，我们首先在项目树的`res`文件夹下添加另一个名为`layout-land`的文件夹。

### 注意

资源文件夹名称建立了资源文件与设备特性之间的关联，而不是 Android Studio 的任何特殊行为。

要在 Android Studio 中创建新文件夹，请执行以下步骤：

1.  在项目浏览器窗口中展开**src**文件夹。

1.  展开位于**src**下的**main**文件夹。

1.  在**main**下的**res**文件夹上右键点击。

1.  选择**新建**。

1.  选择**Android 资源目录**以打开**新资源目录**对话框。

1.  选择**布局**作为**资源类型：**。

1.  高亮**可用限定符：**下的**方向**，并点击**>>**按钮将其移到**选定限定符：**。

1.  在**屏幕方向：**下选择**横屏**。

将会出现类似于以下截图的**新资源目录**对话框：

![添加一个备用布局资源](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_02_02_NEW.jpg)

现在，将**layout**资源文件夹中的`activity_main.xml`资源文件复制到**layout-land**资源文件夹中。我们在以下截图中可以看到现在有两个`activity_main.xml`资源文件：

![添加一个备用布局资源](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_02_03_NEW.jpg)

现在，我们可以修改位于`layout-land`文件夹中的`activity_main.xml`资源文件，以便当手机处于横屏方向时，正确地排列碎片。首先，我们将`LinearLayout`元素的垂直方向改为水平方向。然后，将每个碎片的`layout_width`改为`0dp`，`layout_height`改为`match_parent`。我们可以将每个碎片的`layout_weight`值设置为`1`，这样`LinearLayout`就会将它们从左到右均匀分布。

更新的资源文件如下所示：

```java
<LinearLayout
    android:orientation=""horozontal""
    android:layout_width=""match_parent""
    android:layout_height=""match_parent""
    ">

  <!-- List of Book Titles -->
  <fragment
      android:layout_width=""0dp""
      android:layout_height="" match_parent""
      android:layout_weight=""1""
      android:name=""com.jwhh.fragments.BookListFragment""
      android:id=""@+id/fragmentTitles""/>

  <!-- Description of selected book -->
  <fragment
      android:layout_width=""0dp""
      android:layout_height=""match_parent""
      android:layout_weight=""1""
      android:name=""com.jwhh.fragments.BookDescFragment""
      android:id=""@+id/fragmentDescription""/>
</LinearLayout>
```

仅仅是将这个简单的资源文件添加到我们的项目中，应用程序现在就可以在横屏模式下运行时，在设备上并排显示标题列表和书籍描述，如下面的截图所示：

![添加一个替代布局资源](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_02_04.jpg)

在运行时，当`MainActivity`类加载`R.layout.activity_main`资源时，Android 资源系统会返回适合该方向版本的`activity_main.xml`资源文件。当用户将设备旋转到不同的方向时，Android 会自动重新创建活动，并加载适合新方向的相关资源。

Android 环境检测到各种设备形态因数的特性。通过利用碎片，我们可以创建一个应用程序，只需提供不同的布局资源文件，就可以轻松地适应设备差异，这些文件可以像拼图一样调整我们的碎片位置。

如果没有碎片（Fragments），我们就需要为活动（Activity）提供完整的布局，包括单选按钮、文本视图等，在两个布局文件中都要包含。这样我们就会发现自己需要维护两个复杂且几乎相同的文件。通过使用碎片，各个独立的部分是自包含且不重复的。碎片以一种简单的方式修改布局，并简化我们的应用程序维护工作。

### 根据屏幕大小管理碎片布局

我们用来适应设备方向差异的相同技术可以进一步应用，以处理屏幕尺寸的差异。Android 资源系统具有对设备屏幕尺寸的认知，因此支持创建相应的资源文件夹。资源选择可以基于一般的屏幕尺寸组或特定的屏幕尺寸限制。

设备屏幕尺寸的差异是使用布局资源管理碎片的最常见原因之一。在这种情况下，了解如何使用布局资源处理屏幕尺寸的差异对于有效地使用碎片至关重要。

#### 资源屏幕尺寸组

每个 Android 设备的配置信息包括该设备所属的屏幕尺寸组。四个屏幕尺寸组分别是小型、正常、大型和特大。

### 注意

有关每组屏幕尺寸的具体信息，请参见[Android 文档](http://developer.android.com/guide/practices/screens_support.html#range)中的*支持屏幕范围*部分。

正如我们为横屏方向创建了一个特定的布局资源文件，我们也可以创建一个针对特定屏幕尺寸组的布局资源文件。通过将资源文件放置在适当命名的资源文件夹中，我们将资源文件与所需的屏幕尺寸组关联起来。例如，我们将为大型屏幕尺寸组设计的布局资源文件放置在`layout-large`资源文件夹中。

屏幕尺寸组的划分可追溯到 Android 早期时代，当时在处理现在存在的各种设备形态因素方面实际经验很少。随着时间的推移，Android 设备形态因素的数量增长，文件尺寸组被证明是一个不太理想的解决方案。屏幕尺寸组的问题源于两个主要问题：

1.  组的大小范围并不一致应用，导致组内的大小范围相互重叠。一个 7 英寸屏幕的设备可能被归类为大型，而另一个同样尺寸屏幕的设备可能被归类为 xlarge。

1.  有时尺寸组过于宽泛。例如，大型组包括了 5 英寸屏幕的设备和 7 英寸屏幕的设备。这些屏幕尺寸往往有非常不同的布局要求。5 英寸屏幕的设备更适合使用类似智能手机的手持式布局，而 7 英寸屏幕的设备更适合使用平板式布局。

尺寸组仍然在使用中，因为它们是处理 API 级别 13 之前设备屏幕尺寸差异的最佳选择。幸运的是，目前使用的 Android 设备中不到一半是 API 级别 13 之前的，这一比例正在迅速缩小。

### 注意

要了解按 API 级别或屏幕尺寸组划分的设备分布情况，请参见[Android 开发者](http://developer.android.com/about/dashboards)提供的*Dashboards*。

#### 资源屏幕尺寸限定符

在 API 级别 13（Android 3.2）中，Android 引入了比屏幕尺寸组更实质性的改进，即资源屏幕尺寸限定符。资源屏幕尺寸限定符允许我们将资源与特定的屏幕尺寸要求相关联。使用屏幕尺寸限定符，我们可以非常详细地控制与每种设备形态因素关联的布局资源。

为了避免处理各种屏幕像素密度和物理屏幕尺寸带来的复杂性，Android 在管理屏幕大小时使用了一个标准化的度量单位，称为**密度独立像素**（**dp**）。如果你已经在 Android 领域工作了一段时间，你可能已经很熟悉密度独立像素，因为它们是在 Android 用户界面内定位和调整视图大小时的首选度量单位。

`dp` 总是等同于 160 dpi 设备上像素的物理尺寸，因此提供了一个与设备物理像素大小无关的恒定度量单位。例如，一个 7 英寸显示设备可能有 1280x720 的物理像素计数，而另一个 7 英寸显示设备有 1920x1080 的物理像素计数，但这两个设备的 dp 计数大约都是 1000x600。Android 平台负责处理密度独立像素与设备物理像素之间的映射细节。

Android 提供了三种屏幕尺寸限定符：最小宽度、可用屏幕宽度和可用屏幕高度：

+   **最小宽度屏幕尺寸限定符：**这在 Android Studio 的新目录资源对话框中被称为最小屏幕宽度。它对应于屏幕最窄点的设备独立像素数，与设备方向无关。改变设备方向不会改变设备的最小宽度。我们通过添加 `sw`，然后是所需的屏幕尺寸（以设备独立像素为单位），再加上 `dp` 来指定基于设备最小宽度的资源文件夹名称。例如，至少有 600 dp 最小宽度的设备所包含的布局资源文件夹名为 `layout-sw600dp`。

+   **可用宽度屏幕尺寸限定符：**这在 Android Studio 的新目录资源对话框中被称为屏幕宽度。它对应于设备当前方向上从左到右测量的设备独立像素数。改变设备方向会改变可用宽度。我们通过添加 `w`，然后是密度独立像素的宽度，再加上 `dp` 来指定基于可用宽度的资源文件夹名称。一个包含至少 600 dp 可用宽度的设备所使用的布局资源文件夹名为 `layout-w600dp`。

+   **可用高度屏幕尺寸限定符：**这在 Android Studio 的新目录资源对话框中被称为屏幕高度。它对应于从上到下测量的设备独立像素数，但除此之外，其行为与可用宽度屏幕尺寸限定符完全相同，并遵循相同的命名模式，只是使用 `h` 而不是 `w`。一个包含至少 600 dp 可用高度的设备所使用的布局资源文件夹名为 `layout-h600dp`。

### 消除冗余

随着我们的应用程序目标形态因素数量的增长，由于我们可能希望为不同的限定符使用相同的布局资源文件，不同布局资源文件夹内的资源文件管理可能会变得有些复杂。为了演示这个问题，让我们更新我们的应用程序，在其他设备上使用我们目前在横屏设备上使用的`activity_main.xml`资源文件版本。我们将对大型屏幕尺寸组和当前宽度为 600 dp 或更大的设备使用相同的资源文件。

首先，我们在`res`文件夹下创建两个额外的文件夹：`layout-large`和`layout-w600dp`。然后，我们将`layout-land`文件夹中的`activity_main.xml`文件复制到我们刚才创建的两个文件夹中。这样做足够简单，但现在我们面临维护的麻烦。每次我们更改该布局时，都必须确保在所有三个文件夹中都进行更改。

为了避免这种资源文件的重复，我们可以使用布局别名。

#### 布局别名

布局别名功能让我们只需保留每个布局资源文件的单一副本。然后我们可以向资源系统提供信息，告知每种形态因素应选择哪个文件。

首先，我们将`layout-land`资源文件夹中的`activity_main.xml`资源文件重命名为`activity_main_wide.xml`。然后，我们将文件移动到`layout`资源文件夹，并删除`layout-land`文件夹。

我们现在在`res`文件夹下创建一个名为`values-land`的新资源文件夹。在 Android Studio 中创建此文件夹，步骤与之前创建`layout-land`文件夹相同，但需将**资源类型**设置为**values**，而不是**layout**。

在此文件夹内，我们创建一个新的资源文件，文件名无关紧要，但通常包含别名值的文件命名为`refs.xml`，因为它包含了对其他资源的引用列表，所以我们也将这样做。使用 Android Studio 创建文件，请执行以下步骤：

1.  右键点击**values-land**资源文件夹。

1.  选择**新建**。

1.  选择**values**资源文件。

1.  指定`refs.xml`作为文件名。

在`refs.xml`文件中，请确保已经有一个名为`resources`的根元素。在此元素内，添加一个`item`元素，其`type`属性值为`layout`。这表示我们正在为布局资源提供一个别名条目。我们将`name`属性的值设置为默认布局资源的名称，在我们的例子中是`activity_main`。然后，我们将`item`元素的值设置为`@layout/activity_main_wide`。现在完整的`refs.xml`资源文件如下所示：

```java
<resources>
  <item type=""layout"" name=""activity_main"">
    @layout/activity_main_wide
  </item>
</resources>
```

当这个文件存在时，任何调用加载布局资源`R.layout.activity_main`的地方，在应用程序在横屏方向运行时，将改为加载`R.layout.activity_main_wide`。

为了在大屏幕组和当前宽度至少为 600 dp 的设备上添加支持，我们只需创建两个额外的资源文件夹，`values-large` 和 `values-w600dp`，并将 `values-land` 文件夹中的 `refs.xml` 文件复制到这两个文件夹中。现在，`layout` 和 `values` 资源文件夹如下截图所示：

![布局别名](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_02_05_NEW.jpg)

目前我们已经支持所有期望的形态因子，且没有不必要的布局资源文件重复。我们确实重复了 `refs.xml` 文件，但它比 `layout` 资源文件简单得多，且更不可能发生变化。

### 注意

请查看 Android *提供资源* 指南中的 *表 2*，了解 Android 在执行布局别名时的优先顺序，可在 [`developer.android.com/guide/topics/resources/providing-resources.html`](http://developer.android.com/guide/topics/resources/providing-resources.html) 查阅。

## 设计灵活的片段

当我们的用户界面良好分割且具有适应性时，我们需要确保每个片段都能有效地工作，因为布局差异会导致活动内其他片段的行为甚至存在发生变化。当应用程序用户界面被划分为片段时，片段很少完全独立于彼此存在。通常一个用户与一个片段的交互会对同一活动内的其他片段产生影响。在我们的应用程序中，当用户在 `BookListFragment` 中选择一本书时，就会出现这个问题。响应用户的选择，应用程序负责在 `BookDescFragment` 中显示相应的描述。

### 避免紧密耦合

协调片段内容的一个可能解决方案是允许片段直接相互通信。为了在我们的应用程序内协调内容，我们可以在首次创建活动时将 `BookDescFragment` 引用传递给 `BookListFragment`。在 `BookListFragment` 中对每个用户选择的响应中，`BookListFragment` 将直接更新 `BookDescFragment` 中包含的 `TextView`。

尽管这个解决方案易于实施，但它有问题，因为它将两个 `Fragment` 类紧密耦合在一起。`BookListFragment` 片段只能在同时包含 `BookDescFragment` 片段的活动中使用，而且对 `BookDescFragment` 布局进行更改可能会潜在地破坏 `BookListFragment`。我们始终要记住，使用片段的一个关键目标是要做到良好分割和适应性。

### 抽象片段关系

我们可以利用接口提供的抽象，而不是直接创建片段之间的关系。通过定义一个简单的回调接口来表示用户选择书籍的行为，我们可以完全消除片段之间的紧密耦合。`BookListFragment`类可以编写为通过接口提供用户选择的通知。通过在活动中实现该接口，活动可以处理协调`BookListFragment`中的用户选择与更新`BookDeskFragment`中显示的描述。

#### 定义回调接口

回调接口应包括任何与包含片段的活动可能有意义的交互方法。同时，接口不应让活动负担不必要的细节。接口应专注于应用程序级别的动作，如选择一本书，而不是实现级别的动作，如点击一个单选按钮。实现级别的细节应该被隔离在片段内部。我们还应确保在设计接口时不要有任何预定的想法，即活动将如何处理通知。

在`BookListFragment`的案例中，活动唯一感兴趣的动作是用户选择一本书。这告诉我们接口只需要一个方法；我们将这个接口方法称为`onSelectedBookChanged`。我们知道在这个应用程序的案例中，目标是显示所选书籍的描述，因此一个可能性是让`onSelectedBookChanged`方法包含一个书籍描述的参数。传递书籍描述的问题是这样做将限制`BookListFragment`仅用于这一个用例，即显示书籍描述。相反，通过传递书籍的标识符，`BookListFragment`可以用于任何用户选择书籍的用例。为了简单起见，在我们的示例中，我们将使用数组索引作为标识符；在真实场景中，标识符更可能是一个用于在数据存储或服务中定位书籍信息的关键。

我们将新的接口称为`OnSelectedBookChangeListener`。接口如下所示：

```java
public interface OnSelectedBookChangeListener {
  void onSelectedBookChanged(int bookIndex);
}
```

#### 使片段自包含

`BookListFragment`类需要隐藏用户选择的细节，而是将每个选择转换为书籍标识符，在我们的案例中是一个数组索引。首先，我们需要更新`BookListFragment`类以处理单选按钮的选择，实现`RadioGroup.OnCheckedChangeListener`接口如下：

```java
public class BookListFragment extends Fragment
    implements RadioGroup.OnCheckedChangeListener {

  @Override
  public void onCheckedChanged(RadioGroup radioGroup, int id)  {

  }

  // Other members elided for clarity

}
```

在`BookListFragment`类的`onCreateView`方法中，我们将单选组的点击监听器设置为`BookListFragment`类，如下所示：

```java
public View onCreateView(LayoutInflater inflater,
    ViewGroup container, Bundle savedInstanceState) {
  View viewHierarchy = inflater.inflate(
      R.layout.fragment_book_list, container, false);

  // Connect the listener to the radio group
  RadioGroup group = (RadioGroup)
  viewHierarchy.findViewById(R.id.bookSelectGroup);
  group.setOnCheckedChangeListener(this);

  return viewHierarchy;
}
```

确定与选中单选按钮对应的书籍索引有多种方法，如在每个单选按钮上设置标签值或使用查找表。为了简单起见，我们将创建一个包含 switch 语句的简单方法，如下代码所示：

```java
  int translateIdToIndex(int id) {
    int index = -1;
    switch (id) {
      case R.id.dynamicUiBook:
        index = 0 ;
        break;
      case R.id.android4NewBook:
        index = 1 ;
        break;
      case R.id.androidSysDevBook:
        index = 2 ;
        break;
      case R.id.androidEngineBook:
        index = 3 ;
        break;
      case R.id.androidDbProgBook:
        index = 4 ;
        break;
    }

    return index;
  }
```

#### 片段通知

片段总是可以通过 `getActivity` 方法访问放置它的活动。在 `BookListFragment` 类的 `onClick` 方法中，我们可以使用 `getActivity` 方法访问活动，将其转换为 `OnSelectedBookChangeListener` 接口，然后调用 `onSelectedBookChanged` 方法，并传递选中单选按钮的书籍索引，如下代码所示：

```java
public void onCheckedChanged(RadioGroup radioGroup, int id) {
  // Translate radio button to book index    
  int bookIndex = translateIdToIndex(id);

  // Get parent Activity and send notification
  OnSelectedBookChangeListener listener =
      (OnSelectedBookChangeListener) getActivity();
  listener.onSelectedBookChanged(bookIndex);
}
```

现在 `BookListFragment` 类完全负责通知父活动关于用户书籍选择的每次更改。

### 封装片段操作

在 `BookDescFragment` 类中，我们希望封装有关如何更新用户界面的任何细节。我们将通过提供一个接受书籍索引并处理查找和显示书籍描述的简单方法来实现这一点。在实现该方法之前，我们首先需要更新 `BookDescFragment` 类的 `onCreateView` 方法，以获取书籍描述列表，获取到 `TextView` 的引用，该 `TextView` 由 `R.id.bookDescription` 标识，并将两者分配给类级字段，如下所示：

```java
public class BookDescFragment extends Fragment {

  String[] mBookDescriptions;
  TextView mBookDescriptionTextView;

  @Override
  public View onCreateView(LayoutInflater inflater,
    ViewGroup container, Bundle savedInstanceState) {
    View viewHierarchy = inflater.inflate(
        R.layout.fragment_book_desc, container, false);

    // Load array of book descriptions
    mBookDescriptions = getResources().
        getStringArray(R.array.bookDescriptions);
    // Get reference to book description text view
    mBookDescriptionTextView = (TextView)
        viewHierarchy.findViewById(R.id.bookDescription);

    return viewHierarchy;
  }
}
```

我们现在可以添加一个接受书籍索引的 `setBook` 方法，访问适当的书籍描述，并更新 `mBookDescriptionTextView`。`setBook` 方法如下所示：

```java
public void setBook(int bookIndex) {
  // Lookup the book description
  String bookDescription = mBookDescriptions[bookIndex];

  // Display it
  mBookDescriptionTextView.setText(bookDescription);
}
```

### 松散地连接各个部分

合理使用接口和封装可以大大简化任何组件的使用，片段也不例外。通过对 `BookListFragment` 和 `BookDescFragment` 类所做的努力，我们的活动现在可以通过以下三个简单步骤在 `BookListFragment` 中协调用户交互，通过更新 `BookDescFragment`：

1.  实现 `OnSelectedBookChangeListener` 接口。

1.  获取对 `BookDescFragment` 类的引用。

1.  调用 `BookDescFragment` 类的 `setBook` 方法。

首先看第二步。与处理视图不同，活动不能直接引用其包含的片段。相反，片段处理被委托给 `FragmentManager` 类。

每个活动都有 `FragmentManager` 类的唯一实例。`FragmentManager` 类负责访问和管理该活动中的所有片段。活动通过 `getFragmentManager` 方法访问其 `FragmentManager` 实例。

### 注意

在使用 Android Support Library 时，应使用 `FragmentActivity` 类的 `getSupportFragmentManager` 方法，代替标准 `Activity` 类的 `getFragmentManager` 方法来访问当前的 `FragmentManager` 实例。

使用 `FragmentManager`，活动可以通过调用 `FragmentManager.findFragmentById` 方法并传递布局资源中所需片段的 id 值来访问包含的片段。

### 注意

`FragmentManager`是一个重要的类，具有许多强大的功能。我们将在第四章《使用片段事务》中更详细地讨论`FragmentManager`。

通过使用`FragmentManager`访问`BookDescFragment`，我们可以在活动中实现`BookListFragment.OnSelectedBookChangeListener`接口，以更新`BookListFragment`中每个用户选择的显示描述。

```java
public class MainActivity extends Activity
    implements OnSelectedBookChangeListener{

  @Override
  public void onSelectedBookChanged(int bookIndex) {
    // Access the FragmentManager
    FragmentManager fragmentManager = getFragmentManager();
    // Get the book description fragment
    BookDescFragment bookDescFragment = (BookDescFragment)   
        fragmentManager.findFragmentById(R.id.fragmentDescription);
    // Display the book title
    if(bookDescFragment != null)
      bookDescFragment.setBook(bookIndex);
  }

  // other members elided for clarity
}
```

# 片段保护免受预期之外的影响

用户界面灵活性的真正考验是在遇到意外的变更请求时，设计和实现能否经受住考验。一个设计良好的基于片段的用户界面可以让我们创建出能够以最小的影响力和代码变化而进化和改变的令人难以置信的动态用户界面。举个例子，让我们对应用程序进行可能是一个重大设计更改。

目前，该应用总是在同一个活动中显示书籍列表和描述。唯一的区别是片段是相对于彼此垂直还是水平放置。设想我们收到了用户的反馈，他们不喜欢在竖屏手机上查看应用时的显示方式。在竖屏手机上查看时，他们希望列表和描述出现在不同的活动中。在其他所有情况下，他们希望应用继续同时并排显示列表和描述。

## 演进布局资源文件

首先，我们在`layout`资源文件夹中创建`activity_main.xml`资源文件的副本，并将其命名为`activity_book_desc.xml`。在 Android Studio 中执行以下步骤来完成此操作：

1.  在项目资源管理器窗口中右键点击`activity_main.xml`文件并选择**复制**。

1.  右键点击`layout`文件夹并选择**复制**。

1.  将文件名更改为`activity_book_desc.xml`。

从`activity_book_desc.xml`文件中移除`BookListFragment`的片段元素，使其现在只显示`BookDescFragment`，如下代码所示：

```java
<LinearLayout
    "
    android:orientation=""vertical""
    android:layout_width=""match_parent""
    android:layout_height=""match_parent""
    ">

  <!--  Description of selected book  -->
  <fragment
      android:layout_width=""match_parent""
      android:layout_height=""0dp""
      android:layout_weight=""1""
      android:name=""com.jwhh.fragments_after.BookDescFragment""
      android:id=""@+id/fragmentDescription""
      tools:layout=""@layout/fragment_book_desc""/>

</LinearLayout>
```

在`activity_main.xml`资源文件中，移除`BookDescFragment`，现在它看起来如下所示：

```java
<LinearLayout
    "
    android:orientation=""vertical""
    android:layout_width=""match_parent""
    android:layout_height=""match_parent""
    ">

  <!--    List of Book Titles  -->
  <fragment
      android:layout_width=""match_parent""
      android:layout_height=""0dp""
      android:layout_weight=""1""
      android:name=""com.jwhh.fragments_after.BookListFragment""
      android:id=""@+id/fragmentTitles""
      tools:layout=""@layout/fragment_book_list""/>

</LinearLayout>
```

现在我们为每个活动都有了布局资源。请记住，这些更改不会影响使用`activity_main_wide.xml`资源文件的场景下的应用外观。

## 创建书籍描述活动

为了显示书籍描述，我们添加了一个名为`BookDescActivity`的简单活动，它使用`activity_book_desc.xml`布局资源。该活动依赖于“Intent extra”传递书籍索引。由于`BookDescFragment`包含了显示书籍描述所需的所有逻辑，我们可以简单地获取对`BookDescFragment`的引用，并像在`MainActivity`类中一样设置书籍索引，如下所示：

```java
public class BookDescActivity extends Activity {
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_book_desc);

    // Retrieve the book index from the Activity Intent
    Intent intent = getIntent();
    int bookIndex = intent.getIntExtra(""bookIndex"", -1);

    if (bookIndex != -1) {
      // Use FragmentManager to access BookDescFragment
      FragmentManager fm = getFragmentManager();
      BookDescFragment bookDescFragment = (BookDescFragment)
          fm.findFragmentById(R.id.fragmentDescription);
      // Display the book title
      bookDescFragment.setBook(bookIndex);
    }
  }
}
```

## 让`MainActivity`类具有适应性

`MainActivity`类现在需要做一些额外的工作，因为其中包含的特定片段会有所变化。在至少 600 dp 宽的屏幕设备上运行或在大型屏幕设备组中运行时，`MainActivity`类总是包含`BookDescFragment`的实例。另一方面，在其他设备上运行时，`BookDescFragment`的存在将取决于设备的当前方向。我们可以在`MainActivity`类中添加代码以测试所有这些不同的场景，或者我们可以采取更简单的方法，即检查活动是否包含`BookDescFragment`类的实例。

使用这种方法，我们让`MainActivity`类的`onSelectedBookChanged`方法来检查`FragmentManager`返回的`BookDescFragment`的有效性。如果`FragmentManager`返回有效引用，方法可以像之前一样在`BookDescFragment`上调用`setBook`。如果返回的引用无效，`onSelectedBookChanged`方法会调用带有`Intent`实例的`startActivity`，该实例包含显示`BookDescActivity`所需的信息，其中包括作为额外参数的`bookIndex`，如下代码所示：

```java
public void onSelectedBookChanged(int bookIndex) {
  // Access the FragmentManager
  FragmentManager fm = getFragmentManager();
  // Get the book description fragment
  BookDescFragment bookDescFragment = (BookDescFragment)
      fm.findFragmentById(R.id.fragmentDescription);

  // Check validity of fragment reference
  if(bookDescFragment == null || !bookDescFragment.isVisible()){
    // Use activity to display description
    Intent intent = new Intent(this, BookDescActivity.class);
    intent.putExtra(""bookIndex"", bookIndex);
    startActivity(intent);
  }
  else {
    // Use contained fragment to display description
    bookDescFragment.setBook(bookIndex);
  }
}
```

注意到`if`语句检查`bookDescFragment`的有效性。在大多数情况下，仅需要简单检查引用是否为空。唯一的例外是在手持设备上，用户在横屏模式下查看应用程序后，将设备旋转为竖屏。在这种情况下，`BookDescFragment`实例不可见，但活动的`FragmentManager`实例可能会缓存来自横屏布局的不可见实例的引用。因此，我们同时检查引用是否为空和是否可见。我们将在接下来的两章中讨论片段的生命周期、创建和缓存的细节。

现在我们的应用程序已经内置了适应性。使用`activity_main_wide.xml`资源文件的场景看起来一如既往。在竖屏手持设备上，我们的应用程序为用户提供两个独立的界面：一个用于书籍列表，另一个用于书籍描述。应用程序现在在竖屏手持设备上的显示如下所示：

![使 MainActivity 类具有适应性](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_02_06_NEW.jpg)

# 总结

片段为我们应用程序提供了难以通过其他方式实现的用户界面灵活性。通过适当设计我们的应用程序以使用片段，并将片段资源与适当的设备特性相关联，我们能够构建出能够自动适应各种 Android 设备形态的应用程序，同时只需编写最少的代码量。

在下一章中，我们将深入研究片段的生命周期，并探讨如何利用片段生命周期来创建更具响应性的用户界面，以及利用专门的`Fragment`类。


# 第三章：片段生命周期与专业化

本章讨论了片段的生命周期与活动生命周期的关系，并在生命周期的各个阶段演示了适当的编程操作。引入了特殊用途的片段类`ListFragment`和`DialogFragment`，涵盖了它们的使用以及它们在活动生命周期中的行为与标准片段的不同之处。

本章节涵盖了以下主题：

+   片段设置/显示事件序列

+   片段拆卸/隐藏事件序列

+   使用`ListFragment`类

+   使用`DialogFragment`类

+   作为传统的`Dialog`类与`DialogFragment`类交互

+   将现有的`Dialog`类包装在`DialogFragment`类中

到本章末，我们将能够协调片段在它们宿主活动中的设置和拆卸，并能够有效地利用`ListFragment`和`DialogFragment`类。

# 理解片段生命周期

开发 Android 应用程序的挑战之一是确保我们的应用程序能够有效地处理应用程序活动的生命周期。在应用程序的生命周期中，一个给定的活动可能会被创建、销毁和重新创建多次。例如，用户将设备从纵向旋转到横向，或者相反，通常会导致可见活动完全销毁并使用适合新方向资源的活动重新创建。那些不能与这一自然生命周期有效协作的应用程序经常会崩溃或表现出其他不良行为。

众所周知，每个片段实例只存在于单一活动中；因此，该片段必须以某种方式与活动生命周期协作。实际上，片段不仅与活动生命周期协作，而且与之紧密相连。

在设置和显示阶段以及隐藏和拆卸阶段，片段提供了与活动许多相同的与生命周期相关的回调方法。此外，片段还提供了与包含活动的片段关系相关的其他生命周期相关的回调方法。

随着我们的应用程序变得更加复杂，我们使用更多专业化的片段类实现，理解片段类的生命周期及其与活动生命周期的关系是至关重要的。

### 注意

如果你对 Android 活动生命周期回调方法的基础知识不熟悉，请参阅*Android Activity*文档中的*Activity Lifecycle*部分，链接为：[`developer.android.com/reference/android/app/Activity.html#ActivityLifecycle`](http://developer.android.com/reference/android/app/Activity.html#ActivityLifecycle)。

## 理解片段的设置和显示

片段的设置和显示是一个多阶段的过程，涉及片段与活动的关联、片段的创建以及将活动移动到运行状态（也称为恢复或活动状态）的标准生命周期事件。理解生命周期事件的行为和相关回调方法对于有效使用片段至关重要。一旦我们了解了生命周期事件和回调方法，我们就会研究事件回调方法是如何被使用的。

下图展示了在设置和显示期间，片段和活动上发生的生命周期相关回调方法的调用顺序：

![理解片段设置和显示](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095OS_03_01.jpg)

如你所料，在大多数情况下，片段的设置和显示第一步发生在活动的`onCreate`方法中。在大多数情况下，活动在其`onCreate`回调方法中调用`setContentView`方法，这会加载布局资源并触发活动与包含片段的关联。

注意接下来发生的事情。在片段被创建之前，该片段就已经与活动关联。首先，片段会通过`onAttach`回调方法得知这一关联，并获得对活动的引用。然后活动得到通知，并通过`onAttachFragment`回调方法获得对片段的引用。

尽管在创建片段之前将片段与活动关联可能看起来有些意外，但这样做是有用的。在许多情况下，片段在创建过程中需要访问活动，因为活动通常包含片段将显示或对片段创建过程重要的信息。

片段与活动关联后，片段在`onCreate`方法中进行一般的创建工作，然后在`onCreateView`方法中构建包含的视图层次结构。

当一个活动包含多个片段时，Android 会为一个片段连续调用四个方法：`Fragment.onAttach`、`Activity.onAttachFragment`、`Fragment.onCreate`和`Fragment.onCreateView`，然后再对下一个片段调用这些方法。这使得每个片段在下一个片段开始该过程之前，可以完成关联和创建的过程。

调用这四个方法的一系列操作完成所有片段后，其余的设置和显示回调方法会依次为每个片段单独调用。

活动执行完其`onCreate`方法后，Android 会调用每个片段的`onActivityCreated`方法。`onActivityCreated`方法表明，由活动布局资源创建的所有视图和片段现在已完全构建，可以安全访问。

在这一点上，片段在活动的同名方法各自被调用之后，紧接着会收到标准的生命周期回调，即`onStart`和`onResume`方法。在片段的`onStart`和`onResume`方法中执行的工作与在活动内对应方法中执行的工作非常相似。

对于许多片段来说，它们生命周期这部分唯一被重写的方法是`onCreate`和`onCreateView`方法，正如我们在前面章节的例子中所看到的那样。

### 避免方法名称混淆

活动和片段类有许多名称常见的方法回调，这些常见名称的方法大多数具有共同的目的。一个重要的例外是`onCreateView`方法。这个方法对于每个类的目的都大不相同。

如前所述，Android 调用`Fragment`类的`onCreateView`方法，让片段有机会创建并返回其包含的视图层次结构。这个方法通常在片段内部被重写。

在`Activity`类中同名的方法在膨胀布局资源的过程中会被`LayoutInflater`类多次调用。大多数活动实现并不重写这个方法。

## 理解片段的隐藏和销毁

正如片段在设置和显示阶段与活动表现相似一样，在隐藏和销毁阶段，它们的行为也类似，如下图所示：

![理解片段的隐藏和销毁](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095OS_03_02.jpg)

在隐藏和销毁的初期，片段的行为与活动类似。当用户切换到另一个活动时，每个片段的`onPause`、`onSaveInstanceState`和`onStop`方法会被调用。对于每个方法，首先调用片段的实现，然后调用活动的实现。

在调用`onStop`方法之后，片段的行为开始与活动略有不同。与将片段创建与片段视图层次创建分离一致，片段视图层次的销毁也是与片段销毁分离的。在调用活动的`onStop`方法之后，会调用片段的`onDestroyView`方法，表示由片段的`onCreateView`方法返回的视图层次正在被销毁。然后调用片段的`onDestroy`方法，接着是片段的`onDetach`方法。此时，片段与活动没有任何关联，任何对`getActivity`方法的调用都将返回 null。

对于包含多个片段的活动，在开始调用下一个片段的三个方法序列之前，Android 会为一个单独的片段调用`onDestroyView`、`onDestroy`和`onDetach`这三个方法的序列。这类似于 Android 将附加和创建每个片段的过程分组在一起的方式，对销毁和分离每个片段的过程进行分组。当所有片段的这个序列完成后，Android 然后调用活动的`onDestroy`方法。

## 最大化可用资源

在大多数情况下，片段的生命周期管理与活动非常相似。然而，有一个重要的例外：片段创建和销毁的两阶段性质。片段将片段的创建和销毁与其包含的视图层次结构分离。这是因为片段有能力在不存在片段视图层次结构的情况下与活动存在并关联。

在许多场景中，活动可能包含多个片段，但在任何时刻只显示这些片段的一个子集。在这种情况下，包含的片段都可以调用其`onAttach`和`onCreate`方法。但是，直到应用程序需要使该片段的内容可见时，才会调用每个片段的`onCreateView`方法。同样，当需要隐藏片段内容时，只调用片段的`onDestroyView`方法，而不是`onDestroy`和`onDetach`方法。

当在活动中动态管理片段时，这种行为便发挥作用。这种行为允许将片段与活动关联的开销以及初始化片段状态的过程只发生一次，同时能够轻松地改变片段视图层次结构的可见性。当我们使用`FragmentTransaction`类明确管理片段的可见性，以及在某些管理片段的操作栏特性中，这一点非常重要。我们将在接下来的两章中讨论这些问题。

### 管理片段状态

对于许多片段实现来说，生命周期序列中最重要的回调方法是`onSaveInstanceState`。与活动一样，这个回调方法为片段在销毁之前提供了持久化任何状态的机会，例如当用户移动到另一个活动或当用户将设备旋转到不同的方向时。在这两种情况下，活动和包含的片段可能会被完全拆除并重新创建。通过在`onSaveInstanceState`方法中持久化片段状态，该状态后来会在`onCreate`和`onCreateView`方法中传递回片段。

在管理片段的状态时，你需要确保将那些与片段整体存在相关的通用工作与特定于设置视图层次结构的工作分开。任何与片段存在相关的昂贵初始化工作，如连接数据源、复杂计算或资源分配，都应该在`onCreate`方法中而不是`onCreateView`方法中进行。这样，如果只是片段的视图层次结构被销毁而片段本身保持完整，你就可以避免不必要地重复昂贵的初始化工作。

# 特定目的片段类

既然我们已经理解了片段的生命周期，我们可以看看`Fragment`类的几种特殊版本。在了解这些特殊类时，请记住，它们最终都继承自`Fragment`类，因此具有相同生命周期行为。这些特殊类中的许多都会影响在生命周期的各个阶段可以安全执行的操作，有些类甚至还会添加自己的生命周期方法。为了有效地使用这些类，理解每个类及其与片段生命周期的交互是至关重要的。

## 列表片段

最简单且最有用的片段派生类之一是`ListFragment`类。`ListFragment`类提供了一个封装了`ListView`的片段，顾名思义，它非常适合用于显示数据列表。

### 将数据与列表关联

与基础的`Fragment`类不同，我们不需要为`ListFragment`类重写`onCreateView`回调方法。`ListFragment`类提供了一个标准的外观，并且我们只需要关联一些数据。`ListFragment`类完成了创建视图层次结构并显示数据的所有工作。

我们通过调用`ListFragment`类的`setListAdapter`方法并将实现了`ListAdapter`接口的对象引用传递给该方法，来与`ListFragment`类关联数据。Android 提供了许多实现此接口的类，如`ArrayAdapter`、`SimpleAdapter`和`SimpleCursorAdapter`。你使用的具体类将取决于你的源数据存储方式。如果标准的 Android 类不能满足你的特定需求，你可以相对容易地创建一个自定义实现。

### 注意

要讨论创建自定义列表适配器，请参阅 Android 教程《*显示快速联系人徽章*》在[`developer.android.com/training/contacts-provider/display-contact-badge.html`](http://developer.android.com/training/contacts-provider/display-contact-badge.html)。

调用`setListAdapter`要求`ListFragment`的视图层次结构必须完全构建完成。因此，我们通常不会在`onActivityCreated`回调方法之前调用`setListAdapter`方法。

`ListFragment`类包装了一个`ListView`类的实例，通过`getListView`方法可以访问到它。在大多数情况下，我们可以直接与包含的`ListView`实例交互，并利用`ListView`类提供的任何功能。一个非常重要的例外是在我们设置`ListAdapter`实例时。`ListFragment`和`ListView`类都公开了一个`setListAdapter`方法，但我们必须确保使用`ListFragment`版本的方法。

`ListFragment`类依赖于在`ListFragment.setListAdapter`方法中发生的某些初始化行为；因此，直接在包含的`ListView`实例上调用`setListAdapter`方法会绕过此初始化行为，可能导致应用程序变得不稳定。

### 将数据与显示分离

迄今为止，我们的应用程序使用一组固定的`RadioButton`视图来显示书籍列表。使用固定布局来显示这类选项通常不是一个好的选择，因为书籍列表的任何更改都需要我们进入并直接修改片段布局。实际上，我们更愿意有一个与特定标题无关的布局。我们可以编写代码动态生成`RadioButton`视图，但有一种更简单的方法。我们可以使用`ListFragment`类。

通过将我们的应用程序切换到使用`ListFragment`类，我们可以简单地将书名列表存储在数组资源中，并将该数组资源的内容与`ListFragment`实例关联。在添加更多标题或需要更改其中一个标题时，我们只需修改数组资源文件。我们没有必要对实际的片段布局进行任何更改。

我们的应用程序已经将所有书名作为单独的字符串资源存储，因此我们只需要为它们添加一个数组资源。我们将在`values`资源文件夹中的`arrays.xml`资源文件中添加书名数组，该文件夹中我们已经有了一个定义用来保存书籍描述列表的数组资源。

在`arrays.xml`资源文件的`resources`根元素中，添加一个带有`name`属性值为`bookTitles`的`string-array`元素。在`string-array`元素内，为每个书名添加一个引用每个标题字符串资源的`item`。我们要确保书籍标题数组条目的列出顺序与`bookDescription`数组条目相同，因为当通知活动用户选择的书籍时，我们使用数组索引作为每本书的 ID 值。书名和描述数组的数组资源条目如下所示：

```java
<resources>
  <!-- Book Titles -->
  <string-array name="bookTitles">
    <item>@string/dynamicUiTitle</item>
    <item>@string/android4NewTitle</item>
    <item>@string/androidSysDevTitle</item>
    <item>@string/androidEngineTitle</item>
    <item>@string/androidDbProgTitle</item>
  </string-array>

  <!-- Book Descriptions -->
  <string-array name="bookDescriptions">
    <item>@string/dynamicUiDescription</item>
    <item>@string/android4NewDescription</item>
    <item>@string/androidSysDevDescription</item>
    <item>@string/androidEngineDescription</item>
    <item>@string/androidDbProgDescription</item>
  </string-array>
</resources>
```

将标题存储为数组资源后，我们现在可以轻松创建一个`ListFragment`派生类来显示书名。

#### 创建`ListFragment`派生类

第一步是为我们的项目添加一个新类。为此，我们将创建一个名为 `BookListFragment2` 的新类，该类继承自 `ListFragment` 类，如下面的代码行所示：

```java
class BookListFragment2 extends ListFragment {  }
```

接下来，我们重写 `onActivityCreated` 方法，如下所示：

```java
public void onActivityCreated(Bundle savedInstanceState) {
  super.onActivityCreated(savedInstanceState);

  String[] bookTitles = 
      getResources().getStringArray(R.array.bookTitles);
  ArrayAdapter<String> bookTitlesAdapter = 
      new ArrayAdapter<String>(getActivity(),
      android.R.layout.simple_list_item_1, bookTitles);

  setListAdapter(bookTitlesAdapter);
}
```

在 `onActivityCreated` 方法中，我们首先调用所有扩展 `ListFragment` 的类所需的基类实现。然后加载 `bookTitles` 数组资源，并将其与名为 `bookTitlesAdapter` 的 `ArrayAdapter` 类实例关联。数组适配器将上下文作为第一个参数，我们通过访问活动来获取它，将数组作为第三个参数。第二个参数是用于布局列表中每个条目的资源的 ID。这个资源可以是自定义资源或 Android 内置资源之一。在我们的例子中，我们使用的是内置的 Android 布局资源 `android.R.layout.simple_list_item_1`，它为 `ListView` 中的每一行显示一个字符串值。最后一步是调用 `setListAdapter` 方法，并传递 `bookTitlesAdapter`。

### 注意

为 `ListFragment` 类创建一个自定义布局资源与为 `ListView` 类创建类似，这在 Android 开发者文档中有详细讨论：[`developer.android.com/reference/android/app/ListFragment.html.`](http://developer.android.com/reference/android/app/ListFragment.html.)

#### 处理 `ListFragment` 项目选择的操作

为了使我们的应用程序正常工作，每次用户选择其中一个标题时，我们需要通知活动。由于我们使用接口来将片段与活动松散耦合，因此这个任务相当简单。

我们首先重写 `ListFragment` 类的 `onListItemClick` 方法。当用户在 `ListFragment` 实例中选择一个条目时，`ListFragment` 类会调用 `onListItemClick` 方法。`onListItemClick` 方法接收几个与选择相关的参数，包括基于零的选择位置。我们的 `ListFragment` 从数组中加载，因此这个位置值对应于所选标题的数组索引。

由于 `position` 参数值直接对应于数组索引，我们只需获取对活动的引用，将其转换为我们的 `OnSelectionChangeListener` 接口，并调用接口的 `onSelectedBookChanged` 方法，传递 `position` 参数值，如下面的代码所示：

```java
public void onListItemClick(ListView l, View v, int position, long id) {
  // Access the Activity and cast to the inteface
  OnSelectedBookChangeListener listener =(OnSelectedBookChangeListener) 
      getActivity();

  // Notify the Activity of the selection
  listener.onSelectedBookChanged(position);
}
```

我们应用程序中所有将使用 `BookListFragment2` 类的活动类已经实现了 `OnSelectionChangeListener` 接口，因此无需更改活动类。

#### 更新布局资源

现在，我们更新 `activity_main.xml` 资源文件，使用 `BookListFragment2` 类替代原来的 `BookListFragment` 类，如下面的代码所示：

```java
<LinearLayout
    android:orientation="vertical"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    >

  <!-- List of Book Titles ** using the ListFragment **-->
  <fragment
      android:layout_width="match_parent"
      android:layout_height="0dp"
      android:layout_weight="1"
      android:name="com.jwhh.fragments.BookListFragment2"
      android:id="@+id/fragmentTitles"/>

  <!-- Description of selected book -->
  <fragment
      android:layout_width="match_parent"
      android:layout_height="0dp"
      android:layout_weight="1"
      android:name="com.jwhh.fragments.BookDescFragment"
      android:id="@+id/fragmentDescription"/>
</LinearLayout>
```

我们需要在 `activity_main_wide.xml` 文件中进行相同的更改。

我们现在完全使用 `ListFragment` 类使程序功能完整，如下所示：

![更新布局资源](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_03_03.jpg)

我们现在需要做的任何标题更改都可以在资源文件中完成，不需要更改用户界面代码。

## DialogFragment

到目前为止，我们一直在将片段看作是一种将应用程序用户界面划分为可用显示区域子部分的新方法。尽管片段是新的，但将应用程序用户界面的一部分作为可用显示区域的子部分的概念并不是新的。每当应用程序显示一个对话框时，它实际上就是在这样做。

从历史上看，使用对话框的挑战在于，尽管它们在概念上只是应用程序内的另一个窗口，但我们必须以不同于应用程序用户界面其他方面的处理方式来处理与对话框相关的许多任务。像处理按钮点击这样简单的事情就需要一个特定的对话框接口，`DialogInterface.OnClickListener`，而不是我们在处理非对话框相关部分用户界面代码中的 `click` 事件时使用的 `View.OnClickListener` 接口。更复杂的问题是设备方向改变。对话框会响应方向改变而自动关闭，因此如果用户在对话框可见时改变设备方向，可能会导致应用程序行为不一致。

`DialogFragment` 类消除了与对话框相关的许多特殊处理。使用 `DialogFragment` 类，显示和管理对话框与其他应用程序用户界面方面的处理更为一致。

### 样式

当应用程序显示 `DialogFragment` 类的实例时，`DialogFragment` 实例的窗口最多有三个部分：布局区域、标题和边框。`DialogFragment` 实例总是包含布局区域，但我们可以通过使用 `setStyle` 方法设置 `DialogFragment` 类的样式来控制它是否包括标题和边框。`DialogFragment` 类支持四种样式，每个 `DialogFragment` 类的实例只能应用一种样式。下表展示了四种可用的样式：

| 样式 | 显示标题 | 显示边框 | 接收输入 |
| --- | --- | --- | --- |
| `STYLE_NORMAL` | 是 | 是 | 是 |
| `STYLE_NO_TITLE` | 否 | 是 | 是 |
| `STYLE_NO_FRAME` | 否 | 否 | 是 |
| `STYLE_NO_INPUT` | 否 | 否 | 否 |

请注意，样式会累积移除功能。例如，`STYLE_NO_TITLE` 表示没有标题，而 `STYLE_NO_FRAME` 表示没有边框和标题。如果我们不调用 `setStyle` 方法，Android 会使用 `STYLE_NORMAL` 样式创建 `DialogFragment` 实例。

样式会影响 `DialogFragment` 类的其余行为，因此必须在 `onCreate` 回调方法中设置样式。如果在生命周期中的更晚阶段尝试设置 `DialogFragment` 类的样式，则会被忽略。

如果你希望为对话框提供一种特殊的主题，可以将主题的资源 ID 传递给 `setStyle` 方法。为了允许 Android 根据样式选择一个合适的主题，只需将 0 作为主题资源 ID 传递。以下代码设置 `DialogFragment` 实例不显示标题，并使用该样式的 Android 选择的主题：

```java
class MyDialogFragment extends DialogFragment {
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    setStyle(DialogFragment.STYLE_NO_TITLE, 0);
  }
}
```

### 布局

填充 `DialogFragment` 类实例的布局与标准片段派生类的布局一样。我们只需重写 `onCreateView` 方法并充气布局资源。

```java
public View onCreateView(LayoutInflater inflater, 
    ViewGroup container, Bundle savedInstanceState) {
  View theView = inflater.inflate(R.layout.fragment_my_dialog, 
      container, false);
  return theView;
}
```

为 `DialogFragment` 派生类创建一个布局资源与为任何其他片段派生类创建布局资源完全一样。为了使我们的 `DialogFragment` 实例显示一行文本和两个按钮，我们定义了如下所示的 `fragment_my_dialog.xml` 布局资源：

```java
<LinearLayout 

    android:orientation="vertical"
    android:layout_width="match_parent"
    android:layout_height="match_parent">

  <!-- Text -->
  <TextView
      android:layout_width="fill_parent"
      android:layout_height="0px"
      android:layout_weight="1"
      android:text="@string/dialogSimpleFragmentPrompt"
      android:layout_margin="16dp"/>

  <!-- Two buttons side-by-side -->
  <LinearLayout
      android:layout_width="fill_parent"
      android:layout_height="0px"
      android:orientation="horizontal"
      android:layout_weight="3">
    <Button
        android:id="@+id/btnYes"
        android:layout_width="0px"
        android:layout_height="wrap_content"
        android:layout_weight="1"
        android:text="@string/text_yes"
        android:layout_margin="16dp"/>
    <Button
        android:id="@+id/btnNo"
        android:layout_width="0px"
        android:layout_height="wrap_content"
        android:layout_weight="1"
        android:text="@string/text_no"
        android:layout_margin="16dp"/>
  </LinearLayout>
</LinearLayout>
```

### `DialogFragment` 显示

显示我们的 `DialogFragment` 派生类主要是创建类实例并调用 `show` 方法的问题。但是我们需要记住，尽管我们的 `DialogFragment` 实例显示时看起来像一个标准的对话框，但实际上它是一个片段。像所有片段一样，它由包含活动的 `FragmentManager` 实例管理。因此，在调用 `DialogFragment` 类的 `show` 方法时，我们需要传递对活动 `FragmentManager` 实例的引用，就像以下代码中所做的那样：

```java
MyDialogFragment theDialog = new MyDialogFragment();
theDialog.show(getFragmentManager(), null);
```

通过设置我们派生的 `DialogFragment` 类的风格为 `STYLE_NO_TITLE`，并使用前面展示的 `fragment_my_dialog.xml` 布局资源文件，之前的代码将显示如下内容：

![DialogFragment 显示](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_03_04.jpg)

### 事件处理

`DialogFragment` 类的一个关键价值在于，它提供了比使用传统的 `Dialog` 类时更一致的代码。使用 `DialogFragment` 类的大部分方面与其他片段的工作方式相同。显示对话框不必再像处理应用程序用户界面其他方面那样区别对待。例如，无需特殊处理来应对方向变化。在事件处理方面，这种更高的一致性也显而易见，因为我们的按钮点击事件处理可以使用标准的视图类事件接口。

为了处理按钮点击事件，我们派生的 `DialogFragment` 类只需实现 `View.OnClickListener` 接口。以下代码展示了在类的 `onCreateView` 回调方法中，设置“是”和“否”按钮点击事件，以回调到我们的 `DialogFragment` 派生类：

```java
public View onCreateView(LayoutInflater inflater, 
    ViewGroup container, Bundle savedInstanceState) {
  View theView = inflater.inflate(
      R.layout.fragment_my_dialog, container, false);

  // Connect the Yes button click event and request focus
  View yesButton = theView.findViewById(R.id.btnYes);
  yesButton.setOnClickListener(this);
  yesButton.requestFocus();

  // Connect the No button click event
  View noButton = theView.findViewById(R.id.btnNo);
  noButton.setOnClickListener(this);

  return theView;
}
```

请注意，我们设置按钮点击处理的方式与在任何其他片段内工作或直接在活动中工作时的处理方式相同。

我们也可以以与其他片段相同的方式一致地处理通知活动用户与 `DialogFragment` 派生类的交互。就像我们在前一章中所做的那样，我们的 `DialogFragment` 派生类只需提供一个接口，以通知活动用户选择了哪个可用的按钮，如下代码所示：

```java
public class MyDialogFragment extends DialogFragment 
    implements View.OnClickListener {

  // Interface Activity implements for notification
  public interface OnButtonClickListener {
    void onButtonClick(int buttonId);
  }
  // Other members elided for clarity
}
```

只要活动实现了接口，我们的 `DialogFragment` 派生类就可以通知活动用户点击了哪个按钮。

在按钮点击事件的处理程序中，我们将遵循前一章中的相同模式。我们访问包含的活动，将其转换为预期的接口，并调用接口方法，如下代码所示：

```java
public void onClick(View view) {
  int buttonId = view.getId();

  // Notify the Activity of the button selection  
  OnButtonClickListener parentActivity = 
      (OnButtonClickListener) getActivity();
  parentActivity.onButtonClick(buttonId);

  // Close the dialog fragment
  dismiss();
}
```

注意，在前面方法中有一种特殊处理。就像传统的 `Dialog` 类一样，当不再希望显示 `DialogFragment` 派生类时，我们必须在其上调用 `dismiss` 方法。

### 对话框身份识别

尽管我们将 `DialogFragment` 派生类视为另一个片段，但它仍然有一部分身份与传统 `Dialog` 类相关联。实际上，Android 会将我们的 `DialogFragment` 派生类包装在传统的 `Dialog` 实例中。这发生在特定于 `DialogFragment` 类的回调方法 `onCreateDialog` 中，Android 在调用 `onCreateView` 回调方法之前立即调用它。

`onCreateDialog` 方法返回的 `Dialog` 实例是最终展示给用户的窗口。我们在 `DialogFragment` 派生类中创建的布局只是被包装在 `Dialog` 窗口内。我们可以在生命周期后期访问该 `Dialog` 实例，以访问与 `Dialog` 相关的行为，甚至可以重写方法以提供我们自己的 `Dialog` 实例。

#### 访问与 Dialog 相关的行为

访问我们的 `DialogFragment` 派生类的 `Dialog` 相关行为需要引用在 `onCreateDialog` 方法中创建的 `Dialog` 实例。我们通过调用 `getDialog` 方法来获取该引用。一旦我们有了对 `Dialog` 实例的引用，我们就可以访问类的对话框身份的其他不可用的方面。

当我们创建一个将样式设置为 `STYLE_NORMAL` 的 `DialogFragment` 派生类时，显示的对话框在布局区域上方包括一个标题区域。标题的值只能通过调用包装我们的 `DialogFragment` 实例的 `Dialog` 实例上的 `setTitle` 方法来设置。在处理对话框取消行为时也会出现类似的问题。默认情况下，用户可以通过点击对话框背后的活动来取消对话框。在许多情况下，这可能无法接受，因为我们需要用户在对话框内确认一个选择。以下代码在设置按钮点击处理之后设置了这些与 `Dialog` 相关的行为：

```java
public View onCreateView(LayoutInflater inflater, 
    ViewGroup container, Bundle savedInstanceState) {
  View theView = inflater.inflate(R.layout.fragment_my_dialog, container, false);

  View yesButton = theView.findViewById(R.id.btnYes);
  yesButton.setOnClickListener(this);
  yesButton.requestFocus();

  View noButton = theView.findViewById(R.id.btnNo);
  noButton.setOnClickListener(this);

  // Set the dialog aspects of the dialog fragment
  Dialog dialog = getDialog();
  dialog.setTitle(getString(R.string.myDialogFragmentTitle));
  dialog.setCanceledOnTouchOutside(false);

  return theView;
}
```

代码首先设置对话框标题，然后设置选项以防止用户通过点击活动窗口来关闭对话框。为了使`setTitle`方法的调用生效，我们需要在`onCreate`回调方法中更改对`setStyle`方法的调用，将样式设置为`STYLE_NORMAL`，这样对话框才会具有标题区域。

#### 在片段中包装现有的对话框

有时我们喜欢`DialogFragment`类提供的编程一致性，但同时也想利用从传统的`Dialog`类派生的类所提供的特性。通过重写`DialogFragment`类的`onCreateDialog`方法，我们可以做到这一点。重写`onCreateDialog`方法允许我们用自己创建的`Dialog`实例替换`DialogFragment`类的默认`Dialog`实例。一个典型的使用场景是利用 Android 的`AlertDialog`类。

`AlertDialog`类提供了各种默认行为，允许我们显示文本、图标和按钮，而无需创建布局资源。当我们利用从传统`Dialog`类继承的类时，我们必须记住一点。尽管与我们的类的交互与其他`DialogFragment`派生类一致，但在我们的`DialogFragment`派生类中发生的与传统`Dialog`类的任何交互都将按照传统的`Dialog`类的方式进行。例如，要创建一个利用`AlertDialog`类的`DialogFragment`派生类，需要我们的类实现`Dialog`类处理点击事件的方式，即实现`DialogInterface.OnClickListener`接口，如下面的代码所示：

```java
public class AlertDialogFragment extends DialogFragment 
    implements DialogInterface.OnClickListener{  }
```

在我们类的`onCreateDialog`方法中，我们使用`AlertDialog.Builder`类创建`AlertDialog`实例，就像我们直接显示`AlertDialog`实例一样。在`onCreateDialog`方法中，我们设置`AlertDialog.Builder`实例上的所有选项，包括标题、消息、图标和按钮。但是请注意，我们从不对`AlertDialog.Builder`类的`show`方法进行调用，而是调用其`create`方法。然后我们获取对新创建的`AlertDialog`实例的引用，并从`onCreateDialog`方法中返回它。以下代码展示了所有这些步骤：

```java
public Dialog onCreateDialog(Bundle savedInstanceState) {
  // Create the Builder for the AlertDialog 
  AlertDialog.Builder builder = 
      new AlertDialog.Builder(getActivity());

  // Set the AlertDialog options
  builder.setTitle(R.string.alert_dialog_title)
      .setMessage(R.string.alert_dialog_message)
      .setIcon(R.drawable.ic_launcher)
      .setCancelable(false)
      .setPositiveButton(R.string.text_yes, this)
      .setNegativeButton(R.string.text_no, this);

  // Create and return the AlertDialog
  AlertDialog alertDialog = builder.create();
  return alertDialog;
}
```

我们创建的`Dialog`实例现在作为`DialogFragment`实例的一部分进行管理。我们对`AlertDialogFragment`类执行的其余操作将与我们对创建的其他`DialogFragment`派生类的操作一样。

当我们的应用显示`AlertDialogFragment`类时，它看起来如下面的截图所示：

![在片段中包装现有的对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_03_05.jpg)

请注意，我们不需要重写`onCreateView`回调方法，因为我们在`onCreateDialog`回调方法中创建的`Dialog`实例提供了所需的显示特性。

重写`DialogFragment`类的`onCreateDialog`回调方法是一种强大的技术，它让我们在享受`DialogFragment`类的好处的同时，还能利用我们可能在传统`Dialog`类上已有的投资，无论是内置的如`AlertDialog`类，还是我们自己的代码库中可能拥有的某些自定义`Dialog`类。

# 概述

理解碎片生命周期使我们能够利用碎片的创建和销毁阶段，更有效地管理碎片及其相关数据。通过遵循这个自然生命周期工作，我们可以利用专门的碎片类来创建丰富的用户体验，同时遵循比以前更一致的编程模型。

在下一章中，我们将基于对碎片生命周期理解的基础上，更直接地控制碎片，以便在单个活动中动态地添加和删除它们。


# 第四章：使用片段事务

本章介绍如何在活动中动态管理片段，实现返回按钮的行为，以及监控用户与返回按钮的交互。

让我们看看涵盖的主题：

+   理解`FragmentTransactions`

+   动态添加和移除片段

+   管理与活动关系独立的片段 UI

+   为`FragmentTransactions`添加返回按钮支持

到本章结束时，我们将能够创建使用片段来动态响应用户操作改变屏幕外观的交互式 UI。

# 有意进行屏幕管理

到目前为止，我们认为每个活动总是对应于我们应用程序中的一个单独屏幕。我们只使用片段来表示每个屏幕内的子部分。例如，回想一下我们构建书籍浏览应用程序的方式。在宽屏设备的情况下，我们的应用程序使用一个包含两个片段的单个活动。一个片段显示书籍标题列表，另一个片段显示当前选定书籍的描述。因为这两个片段同时出现在屏幕上，所以我们从单个活动中显示和管理它们。在竖屏手机的情况下，我们选择在单独的屏幕上显示书籍列表和书籍描述。因为这两个片段不会同时出现在屏幕上，所以我们分别在单独的活动中进行管理。

有趣的是，我们的应用程序在两种情况下执行的任务是相同的。唯一的区别是我们能够在屏幕上一次显示多少信息。这个细节让我们不得不在应用程序中添加一个额外的活动。我们还增加了应用程序的复杂性，因为启动新活动的代码比我们在同一活动中简单更新片段的代码要复杂得多。而且，我们的活动中有重复的代码，因为它们都与书籍描述片段交互。

如你所忆，当我们开始在第一章，*片段和 UI 模块化*中讨论片段时，我们提到片段的一个关键价值是它们有助于减少不必要的复杂性、活动的扩散和逻辑的重复。然而，按照目前编写的应用程序来看，我们正在经历所有这些问题。

我们需要进一步发展关于 UI 设计的思路。我们的应用程序中的活动不应只是对恰好适合设备物理显示的信息做出反应，而应该专注于有意管理应用程序中的屏幕与相应活动之间的关系。

对用户来说，进入新屏幕的体验仅仅意味着他们正在查看的视图布局被另一个不同的视图布局所替换。从历史上看，我们倾向于设计我们的应用程序，使得每个活动都有相对固定的布局。因此，将用户移动到新屏幕需要显示一个新活动，但片段为我们提供了另一种选择。

除了使用片段来管理屏幕的逻辑子部分，我们还可以使用它们来管理整个屏幕的逻辑分组。然后我们可以动态管理活动内的片段，以从一个片段更改为另一个片段。这给用户带来了从一个屏幕移动到下一个屏幕的体验，同时也为我们提供了在单个活动中管理通用用户界面元素的便利。

# 动态管理片段

动态管理片段的过程通常涉及多个步骤。这些步骤可能很简单，比如移除一个片段并添加另一个，或者可能更复杂，涉及移除和添加多个片段。在任何情况下，我们需要确保在活动中对片段的所有动态更改，这些更改构成了从应用程序的一个屏幕切换到下一个屏幕，作为一个工作单元一起发生。Android 通过使用`FragmentTransaction`类将步骤分组到事务中来实现这一点。

从概念上讲，`FragmentTransaction`类与其他事务模型的行为一致：开始事务，确定所需的更改，并在识别出该工作单元内的所有更改后提交事务。

当我们准备进行更改时，通过在活动的`FragmentManager`实例上调用`beginTransaction`方法来启动新的`FragmentTransaction`实例，该方法返回对`FragmentTransaction`实例的引用。然后我们使用新的`FragmentTransaction`实例来确定活动内显示的片段列表所需的更改。在我们处于事务中时，这些更改会被排队但尚未应用。最后，当我们确定了所有所需的更改后，我们调用`FragmentTransaction`类的`commit`方法。

一旦事务中的所有更改被应用，我们的应用程序显示就会更新以反映这些更改，给用户一种进入应用程序新屏幕的感觉。尽管在我们的应用程序中发生了许多步骤，但从用户的角度来看，一切就像我们显示了一个新的活动一样。

## 延迟执行事务变更

调用`commit`方法并不会立即应用更改。

当我们使用`FragmentTransaction`类时，我们并不是直接在应用程序用户界面上操作。相反，我们正在构建一个待办事项列表，以在将来对用户界面进行操作。我们在`FragmentTransaction`实例上调用的每个方法都会向列表中添加另一个待办事项。当我们完成待办事项的添加并调用`commit`方法时，这些指令会被打包并发送到主 UI 线程的消息队列中。UI 线程然后遍历这个列表，代表`FragmentTransaction`实例执行实际的用户界面工作。

在大多数情况下，`FragmentTransaction`实例内的工作延迟执行是有效的。然而，如果我们的应用程序代码需要立即在调用`commit`方法后找到一个片段或与由片段添加的视图进行交互，它可能会造成问题。尽管这样的需求通常不是必须的，但有时确实会出现。

如果我们有这样的需求，可以在调用`FragmentTransaction`实例的`commit`方法之后，通过调用`FragmentManager`类的`executePendingTransactions`方法，立即执行`FragmentTransaction`实例的工作。当调用`executePendingTransactions`方法返回时，我们知道所有提交的`FragmentTransaction`工作都已完成。

我们需要小心，只在主 UI 线程上调用`executePendingTransactions`方法；这个方法会导致挂起的前端工作被执行，从而触发与用户界面的直接交互。

## 添加和移除片段

`FragmentTransaction`类上有许多方法可用于操作活动内的片段，但最基本的是`add`和`remove`方法。

`add`方法允许我们将新创建的片段实例放置在活动的特定视图组中，如下所示：

```java
// Begin the transaction
FragmentManager fm = getFragmentManager();
FragmentTransaction ft = fm.beginTransaction();

// Create the Fragment and add
BookListFragment2 listFragment = new BookListFragment2();
ft.add(R.id.layoutRoot, listFragment, "bookList");

// Commit the changes
ft.commit();
```

我们首先使用活动的`FragmentManager`实例创建一个新的`FragmentTransaction`实例。然后创建`BookListFragment2`类的新实例，并将其作为`LinearLayout`视图组的子项附加到活动中，该视图组由`R.id.layoutRoot` ID 值标识。最后，我们提交`FragmentTransaction`实例，表示我们已经完成更改。

我们传递给`add`方法的第三个参数，字符串值`"bookList"`，仅仅是一个标签值。我们可以使用这个标签值，在之后定位片段实例，这与我们使用 id 值的方式类似。当动态添加片段时，我们使用标签作为标识符，而不是 id 值，因为无法将 id 值与动态添加的片段相关联。

当我们准备显示不同的片段时，标签值就派上用场了，因为我们需要有对现有片段的引用，以便传递给`remove`方法，这样我们可以在添加新片段之前移除它。以下代码展示了我们如何更新显示，用`BookDescFragment`类替换之前代码中添加的`BookListFragment2`类：

```java
FragmentManager fm = getFragmentManager();
Fragment listFragment = fm.findFragmentByTag("bookList");
BookDescFragment bookDescFragment = new BookDescFragment();
FragmentTransaction ft = fm.beginTransaction();
ft.remove(listFragment);
ft.add(R.id.layoutRoot, bookDescFragment, "bookDescription");
ft.commit();
```

我们首先使用标签值通过`FragmentManager`类的`findFragmentByTag`方法找到现有的`BookListFragment2`实例。然后我们创建我们想要添加的新片段的实例。现在我们有了要移除的片段和要添加的片段的引用，我们开始片段事务。在事务中，我们通过将引用传递给`FragmentTransaction`类的`remove`方法来移除`BookListFragment2`实例，然后使用`add`方法添加新片段，就像我们之前所做的那样。最后，我们调用`commit`方法以允许进行更改。

这种在特定视图组下移除片段实例并添加另一个来替代的过程经常发生，以至于`FragmentTransaction`类包含了一个名为`replace`的便捷方法。`replace`方法允许我们简单地标识我们想要添加的片段的信息。它处理了移除目标视图组中可能存在的任何其他片段的细节。使用`replace`方法，移除`BookListFragment2`实例并添加`BookDescFragment`实例的代码可以如下编写：

```java
FragmentManager fm = getFragmentManager();
bookDescFragment = new BookDescFragment();
FragmentTransaction ft = fm.beginTransaction();
ft.replace(R.id.layoutRoot, bookDescFragment, "bookDescription");
ft.commit();
```

请注意，这段代码除了方法名之外，与简单添加一个片段的情况完全相同。我们创建自己的片段实例，然后在`FragmentTransaction`调用中，`replace`方法传递目标视图组的 id、片段实例和标签。`replace`方法处理了移除当前可能在`R.id.layoutRoot`视图组中的任何片段的细节。然后它将`BookDescFragment`实例添加到视图组中。

## 支持后退按钮

当我们转向这种将应用屏幕作为片段来管理的模型时，我们需要确保我们为用户提供的是符合他们预期的体验。需要特别关注的一个区域是应用对后退按钮的处理。

当用户与设备上的应用进行交互时，他们会自然地通过不同的应用屏幕向前移动。正常的行为是用户可以通过点击后退按钮随时返回到上一个屏幕。这之所以有效，是因为每次应用显示新的活动时，Android 都会自动将这个活动添加到 Android 后退栈中。这就导致了用户每次点击后退按钮都会返回到上一个活动的预期行为。

这种行为基于一个假设：一个活动等于一个应用程序屏幕；这个假设已不再正确。当我们使用 `FragmentTransaction` 类将用户从一应用程序屏幕过渡到另一屏幕时，应用程序继续显示同一活动，而后退栈对我们的应用程序新屏幕一无所知。这导致应用程序在用户点击后退按钮时似乎会跳过多个屏幕，因为后退栈直接将用户返回到上一个活动，忽略了当前活动所做的任何中间更改。

下图演示了这个问题：

![支持后退按钮](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095OS_04_01.jpg)

1.  应用程序最初调用 `startActivity` 方法以显示 `Activity1` 的实例。`Activity1` 会被自动添加到后退栈，并且当前位于栈顶。

1.  `Activity1` 通过调用 `startActivity` 方法来展示 `Activity2`，后者使用 `FragmentTransaction.add` 方法添加 `FragmentA`。`Activity2` 会被自动添加到后退栈的顶部。

1.  接下来，`Activity2` 使用 `FragmentTransaction.replace` 方法将 `FragmentB` 替换 `FragmentA` 进行展示。对用户来说，应用程序正在显示一个新屏幕，显示 `FragmentB` 的内容。问题是后退栈保持不变。

1.  当用户现在点击后退按钮时，他的预期是应用程序应该显示上一个屏幕 `FragmentA`，但相反，当 Android 弹出后退栈时，它遇到的下一个屏幕是 `Activity1`。

我们通过在显示 `FragmentB` 的 `FragmentTransaction` 实例中调用 `FragmentTransaction` 类的 `addToBackStack` 方法来解决此问题。`addToBackStack` 方法会将事务内的更改添加到后退栈的顶部。这使得用户可以使用后退按钮通过 `FragmentTransaction` 实例创建的应用程序屏幕，就像使用活动显示的屏幕一样。

我们可以在调用 `commit` 方法之前的事务过程中的任何时间点调用 `addToBackStack` 方法。`addToBackStack` 方法可选地接受一个字符串参数，可用于命名后退栈中的位置。如果你希望稍后以编程方式操作后退栈，这很有用，但在大多数情况下，此参数值可以传递为 null。我们很快就会看到 `addToBackStack` 方法的实际应用，因为我们将修改我们的应用程序以使用更自适应的布局。

# 创建自适应应用程序布局

让我们通过更新应用程序使其只使用一个活动来实践动态片段管理讨论。这个单一活动将处理两种场景：宽屏设备上两个片段并排显示，以及竖屏手机上片段显示为两个独立屏幕。提醒一下，在每种场景中，应用程序的外观如下面的屏幕截图所示：

![创建自适应应用布局](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_04_02_NEW.jpg)

在我们的应用程序中，我们将保留宽屏方面的程序不变，因为静态布局管理在那里工作得很好。我们的工作是在应用程序的竖屏手机方面。对于这些设备，我们将更新应用程序的主活动，以动态切换显示包含书籍列表的片段和显示选定书籍描述的片段。

## 更新布局以支持动态片段

在我们编写任何代码来动态管理应用程序中的片段之前，我们首先需要修改针对竖屏手机设备的活动布局资源。该资源包含在`activity_main.xml`布局资源文件中，目前如下所示：

```java
<LinearLayout

    android:orientation="vertical"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    >
  <!--    List of Book Titles  -->
  <fragment
      android:layout_width="match_parent"
      android:layout_height="0dp"
      android:layout_weight="1"
      android:name="com.jwhh.fragments.BookListFragment2"
      android:id="@+id/fragmentTitles"
      tools:layout="@layout/fragment_book_list"/>
</LinearLayout>
```

我们需要对布局资源进行两项更改。第一项是向`LinearLayout`视图组添加一个 id 属性，这样我们可以在代码中轻松找到它。另一个更改是完全移除`fragment`元素。更新后的布局资源现在只包含带有 id 属性值`@+id/layoutRoot`的`LinearLayout`视图组。布局资源现在如下所示：

```java
<LinearLayout

    android:id="@+id/layoutRoot"
    android:orientation="vertical"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    >
</LinearLayout>
```

我们仍然希望应用程序最初显示书籍列表片段，因此移除`fragment`元素可能看起来很奇怪，但这样做对于我们动态管理片段是必要的。最终，我们需要移除书籍列表片段以替换为书籍描述片段。如果我们留下书籍列表片段在布局资源中，我们之后尝试动态移除它会默默失败。

### 注意

只有动态添加的片段才能被动态移除。尝试动态移除使用布局资源中的`fragment`元素静态添加的片段将会默默失败。

## 适应设备差异

当我们的应用程序在竖屏手机设备上运行时，活动需要以编程方式加载包含书籍列表的片段。这是我们之前使用`activity_main.xml`布局资源文件中的`fragment`元素加载的同一`Fragment`类，`BookListFragment2`。在我们加载书籍列表片段之前，我们首先需要确定是否正在运行需要动态片段管理的设备上。记住，对于宽屏设备，我们将保留静态片段管理。

在我们的代码中有几个地方，根据我们使用的布局，我们需要采取不同的逻辑路径，因此我们需要在活动中添加一个`boolean`类级别字段，以便我们可以存储我们是使用动态还是静态片段管理。

```java
boolean mIsDynamic;
```

我们可以查询设备的特定特性，如屏幕大小和方向。但请记住，我们之前的大部分工作是为了配置我们的应用程序，利用 Android 资源系统根据设备特性自动加载适当的布局资源。与其在代码中重复这些特性检查，我们反而可以简单地包含确定已加载哪个布局资源的代码。我们之前为宽显示设备创建的布局资源`activity_main_wide.xml`静态加载了书籍列表片段和书籍描述片段。我们可以在活动的`onCreate`方法中包含以下代码，以确定已加载的布局资源是否包含这些片段之一：

```java
public class MainActivity extends Activity
    implements BookListFragment.OnSelectedBookChangeListener {

  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main_dynamic);

    // Get the book description fragment
    FragmentManager fm = getFragmentManager();
    Fragment bookDescFragment = 
        fm.findFragmentById(R.id.fragmentDescription);

    // If not found than we're doing dynamic mgmt
    mIsDynamic = bookDescFragment == null || 
        !bookDescFragment.isInLayout();
  }

  // Other members elided for clarity
}
```

当`setContentView`方法的调用返回时，我们知道当前设备已加载了适当的布局资源。然后我们使用`FragmentManager`实例查找包含在宽显示设备布局资源中但不在竖屏手机布局资源中的 id 值为`R.id.fragmentDescription`的片段。返回值为`null`表示片段未被加载，因此我们处于需要动态管理片段的设备上。除了对 null 的测试，我们还包含了对`isInLayout`方法的调用，以防止一种特殊情况的发生。

在设备从横屏布局旋转到竖屏的情况下，即使当前方向的活动没有使用片段，标识为`R.id.fragmentDescription`的片段的缓存实例可能仍然存在。通过调用`isInLayout`方法，我们可以确定返回的引用是否是当前加载布局的一部分。这样，我们设置`mIsDynamic`成员变量的测试有效地表明，当找不到（等于`null`）`R.id.fragmentDescription`片段或找到了但不是当前加载布局的一部分（`!bookDescFragment.isInLayout`）时，我们将`mIsDynamic`设置为 true。

## 动态加载启动时的片段

既然我们能够确定是否需要动态加载书籍列表片段，我们就可以将相应代码添加到我们的`onCreate`方法中，如下所示： 

```java
protected void onCreate(Bundle savedInstanceState) {
  super.onCreate(savedInstanceState);
  setContentView(R.layout.activity_main_dynamic);

  // Get the book description fragment
  FragmentManager fm = getFragmentManager();
  Fragment bookDescFragment = 
      fm.findFragmentById(R.id.fragmentDescription);

  // If not found than we're doing dynamic mgmt
  mIsDynamic = bookDescFragment == null || 
      !bookDescFragment.isInLayout();

  // Load the list fragment if necessary
  if (mIsDynamic) {
    // Begin transaction
    FragmentTransaction ft = fm.beginTransaction();

    // Create the Fragment and add
    BookListFragment2 listFragment = new BookListFragment2();
    ft.add(R.id.layoutRoot, listFragment, "bookList");

    // Commit the changes
    ft.commit();
  }
}
```

在检查是否处于需要动态管理片段的设备之后，我们包含`FragmentTransaction`，将`BookListFragment2`类的一个实例添加到由 id 值`R.id.layoutRoot`标识的`LinearLayout`视图组中的活动作为子项。这段代码利用了我们之前对`activity_main.xml`资源文件所做的更改，即移除了`fragment`元素并在`LinearLayout`视图组上包含了 id 值。

既然我们已经动态加载了书籍列表，我们就可以准备删除其他活动了。

## 在片段之间进行转换

如你所知，当用户在`BookListFragment2`类中选择书名时，片段通过传递所选书籍的索引来调用`onSelectedBookChanged`方法，通知主活动。当前的`onSelectedBookChanged`方法如下所示：

```java
public void onSelectedBookChanged(int bookIndex) {
  FragmentManager fm = getFragmentManager();
  // Get the book description fragment
  BookDescFragment bookDescFragment = (BookDescFragment)
      fm.findFragmentById(R.id.fragmentDescription);

  // Check validity of fragment reference
  if(bookDescFragment == null || !bookDescFragment.isVisible()){
    // Use activity to display description
    Intent intent = new Intent(this, BookDescActivity.class);
    intent.putExtra("bookIndex", bookIndex);
    startActivity(intent);
  }
  else {
    // Use contained fragment to display description
    bookDescFragment.setBook(bookIndex);
  }
}
```

在当前实现中，我们使用与在`onCreate`方法中确定加载哪个布局的类似技术；我们尝试在当前已加载的布局中查找书籍描述片段。如果我们找到了，我们就知道当前布局包括该片段，因此可以直接在片段上设置书籍描述。如果我们没有找到，我们就调用`startActivity`方法来显示包含书籍描述片段的活动。

在此场景中，将操作转交给另一个活动并不算太糟糕，因为我们只传递了一个简单的整数值给另一个活动。然而实际上，需要将数据传递给另一个活动的需求可能会变得复杂。特别是如果有一大堆值，或者其中一些值是对象类型，没有额外的编码就不能直接在`Intent`实例中传递。既然我们已经有了在当前活动中与片段交互所需的所有处理，我们更愿意在所有情况下都一致地处理它。

### 消除冗余处理

为了开始，我们可以删除当前实现中处理启动活动的任何代码。我们还可以避免重复检查书籍描述片段，因为我们在`onCreate`方法中已经执行了该检查。相反，我们现在可以检查`mIsDynamic`类级字段以确定适当的处理。考虑到这一点，我们可以最初修改`onSelectedBookChanged`方法，使其现在看起来如下代码所示：

```java
public void onSelectedBookChanged(int bookIndex) {
  BookDescFragment bookDescFragment;
  FragmentManager fm = getFragmentManager();

  // Check validity of fragment reference
  if(mIsDynamic)
    // Handle dynamic switch to description fragment
  else {
    // Use the already visible description fragment
    bookDescFragment = (BookDescFragment)
        fm.findFragmentById(R.id.fragmentDescription);
    bookDescFragment.setBook(bookIndex);
  }
}
```

我们现在检查`mIsDynamic`成员字段以确定适当的代码路径。如果它为真，我们还有一些工作要做，但如果为假，我们可以简单地获取对当前布局中包含的书籍描述片段的引用，并在其上设置书籍索引，就像我们之前所做的那样。

### 动态创建片段

在`mIsDynamic`字段为真时，我们可以通过简单地用书籍描述片段替换我们在`onCreate`方法中添加的书籍列表片段来显示书籍描述片段，代码如下所示：

```java
FragmentTransaction ft = fm.beginTransaction();
bookDescFragment = new BookDescFragment();
ft.replace(R.id.layoutRoot, bookDescFragment, "bookDescription");
ft.addToBackStack(null);
ft.setCustomAnimations(
    android.R.animator.fade_in, android.R.animator.fade_out);
ft.commit();
```

在`FragmentTransaction`中，我们创建了一个`BookDescFragment`类的实例，并调用了`replace`方法，传递了包含我们在`onCreate`方法中添加的`BookListFragment2`实例的同一视图组的 id。我们包含了对`addToBackStack`方法的调用，以便后退按钮可以正确工作，允许用户点击后退按钮返回到书籍列表。

### 注意

代码中包含了对`FragmentTransaction`类的`setCustomAnimations`方法的调用，该方法在用户从一个片段切换到另一个片段时创建了一个淡入淡出效果。

### 管理异步创建

我们还有一个最后的挑战，即设置动态添加的书籍描述片段上的书籍索引。我们最初的想法可能是在创建`BookDescFragment`实例后简单地调用`BookDescFragment`类的`setBook`方法，但首先让我们看一下下面出现的当前`setBook`方法的实现：

```java
public void setBook(int bookIndex) {
  // Lookup the book description
  String bookDescription = mBookDescriptions[bookIndex]; 

  // Display it
  mBookDescriptionTextView.setText(bookDescription);
}
```

方法中的最后一行试图在片段内设置`mBookDescriptionTextView`的值，这是一个问题。记住，我们在`FragmentTransaction`类中所做的工作并不会立即应用到用户界面，而是要在我们调用`commit`方法之后才会执行。因此，`BookDescFragment`实例的`onCreate`和`onCreateView`方法尚未被调用。所以，与`BookDescFragment`实例关联的任何视图都尚未创建。尝试在`mBookDescriptionTextView`实例上调用`setText`方法将导致空引用异常。

一种可能的解决方案是将`setBook`方法修改为能够识别片段的当前状态。在这种情况下，`setBook`方法将检查`BookDescFragment`实例是否已完全创建。如果没有，它将在类级别字段中存储书籍索引值，并在创建过程中稍后自动设置`mBookDescriptionTextView`的值。尽管可能有一些情况需要这种复杂的解决方案，但片段为我们提供了更简单的选择。

`Fragment`基类中包含一个名为`setArguments`的方法。通过`setArguments`方法，我们可以将数据值（也称为参数）附加到片段上，稍后可以在片段的生命周期中使用`getArguments`方法访问这些值。类似于我们将额外数据与`Intent`实例关联时，一个好的实践是在目标类上定义常量来命名参数值。对于非空类型（如整数）的参数默认值，提供常量也是一个好的编程实践，如下所示：

```java
public class BookDescFragment extends Fragment {
  // Book index argument name
  public static final String BOOK_INDEX = "book index";
  // Book index default value
  private static final int BOOK_INDEX_NOT_SET = -1;

  // Other members elided for clarity
}
```

我们将使用`BOOK_INDEX`常量来获取和设置书籍索引值，以及使用`BOOK_INDEX_NOT_SET`常量来指示是否已设置书籍索引参数。

我们现在可以更新`BookDescFragment`类的`onCreateView`方法，以查找可能附加到片段的参数。在我们对`onCreateView`方法进行任何更改之前，先来看看当前的实现方式：

```java
public View onCreateView(LayoutInflater inflater, 
    ViewGroup container, Bundle savedInstanceState) {
  View viewHierarchy = inflater.inflate(
      R.layout.fragment_book_desc, container, false);

  // Load array of book descriptions
  mBookDescriptions = 
      getResources().getStringArray(R.array.bookDescriptions);
  // Get reference to book description text view
  mBookDescriptionTextView = (TextView) 
      viewHierarchy.findViewById(R.id.bookDescription);

  return viewHierarchy;
}
```

由于`onCreateView`方法当前的实现，它只是简单地充气布局资源，加载包含书籍描述的数组，并缓存对加载书籍描述的`TextView`实例的引用。

我们现在可以更新该方法，以查找并使用可能作为参数附加的书籍索引。更新后的方法如下所示：

```java
public View onCreateView(LayoutInflater inflater, 
    ViewGroup container, Bundle savedInstanceState) {
  View viewHierarchy = inflater.inflate(
      R.layout.fragment_book_desc, container, false);

  // Load array of book descriptions
  mBookDescriptions = 
      getResources().getStringArray(R.array.bookDescriptions);
  // Get reference to book description text view
  mBookDescriptionTextView = (TextView) 
      viewHierarchy.findViewById(R.id.bookDescription);

  // Retrieve the book index if attached
  Bundle args = getArguments();
  int bookIndex = args != null ? 
      args.getInt(BOOK_INDEX, BOOK_INDEX_NOT_SET) : 
      BOOK_INDEX_NOT_SET;

  // If we find the book index, use it
  if (bookIndex != BOOK_INDEX_NOT_SET) 
    setBook(bookIndex);

  return viewHierarchy;
}
```

在我们返回片段的视图层次结构之前，我们调用`getArguments`方法以检索可能附加的任何参数。参数作为`Bundle`类的一个实例返回。如果`Bundle`实例非空，我们调用`Bundle`类的`getInt`方法来检索书籍索引并将其分配给`bookIndex`局部变量。`getInt`方法的第二个参数`BOOK_INDEX_NOT_SET`将在片段恰好有附加的参数但不包括书籍索引时返回。虽然这通常不应该发生，但为任何此类意外情况做好准备是个好主意。最后，我们检查`bookIndex`变量的值。如果它包含一个书籍索引，我们调用片段的`setBook`方法来显示它。

### 将其全部放在一起

随着`BookDescFragment`类现在包括支持将书籍索引作为参数附加，我们现在准备完全实现主活动的`onSelectedBookChanged`方法，以包括切换到`BookDescFragment`实例并将书籍索引作为参数附加。现在的方法如下所示：

```java
public void onSelectedBookChanged(int bookIndex) {
  BookDescFragment bookDescFragment;
  FragmentManager fm = getFragmentManager();

  // Check validity of fragment reference
  if(mIsDynamic){
    // Handle dynamic switch to description fragment
    FragmentTransaction ft = fm.beginTransaction();

    // Create the fragment and attach book index
    bookDescFragment = new BookDescFragment();
    Bundle args = new Bundle();
    args.putInt(BookDescFragment.BOOK_INDEX, bookIndex);
    bookDescFragment.setArguments(args);

    // Replace the book list with the description
    ft.replace(R.id.layoutRoot, 
        bookDescFragment, "bookDescription");
    ft.addToBackStack(null);
    ft.setCustomAnimations(
        android.R.animator.fade_in, android.R.animator.fade_out);
    ft.commit();
  }
  else {
    // Use the already visible description fragment
    bookDescFragment = (BookDescFragment)
        fm.findFragmentById(R.id.fragmentDescription);
    bookDescFragment.setBook(bookIndex);
  }
}
```

与之前一样，我们从检查是否进行动态片段管理开始。一旦确定我们在进行，就开始`FragmentTransaction`实例并创建`BookDescFragment`实例。然后我们创建一个新的`Bundle`实例，将书籍索引存储到其中，并使用`setArguments`方法将其附加到`BookDescFragment`实例。最后，我们将`BookDescFragment`实例作为当前片段放置到位，处理回退栈，启用动画，并完成交易。

现在一切就绪。当用户从列表中选择书名时，将调用`onSelectedBookChanged`方法。`onSelectedBookChanged`方法然后创建并显示带有适当书籍索引作为参数的`BookDescFragment`实例。当最终创建`BookDescFragment`实例时，其`onCreateView`方法将然后从参数中检索书籍索引并显示适当的描述。

# 概述

有意识地管理屏幕，使我们摆脱了将每个应用屏幕绑定到单个活动的负担。使用`FragmentTransaction`类，我们能够在活动内动态地在各个片段之间切换，无需为应用中的每个屏幕创建单独的活动类。这有助于防止不必要活动类的增多，更好地组织我们的应用程序，并避免由此产生的复杂性增加。

我们将在下一章看到，这种在一个活动中动态管理多个屏幕的能力，为我们的 Android 应用程序在界面外观和导航行为上提供了更大的灵活性和丰富性。


# 第五章：使用片段创建丰富的导航

本章展示了片段在创建丰富的用户界面导航体验中的作用。

本章节将涵盖以下主题：

+   滑动导航

+   安卓操作栏的角色

+   操作栏与片段之间紧密的关系

+   将菜单与片段关联

+   列表导航

+   标签导航

在本章结束时，我们将能够实现利用片段提供丰富用户导航的解决方案，包括滑动导航、标签导航和下拉列表导航。

# 一个勇敢的新世界

正如我们所见，片段为我们提供了紧密控制和管理工作应用程序用户界面的能力。通过使用`FragmentTransaction`类，我们可以让用户通过简单地切换不同的片段，体验到从一个屏幕移动到另一个屏幕的感觉。这让我们进入了一个全新的思考方式：一个勇敢的应用设计新世界。

当我们以这种方式创建用户界面时，活动充当了一种屏幕管理器的角色，而片段实现了屏幕本身。这种将应用程序的各个屏幕作为活动内的片段进行管理的方法非常强大，它已经成为 Android 平台一些最引人注目的导航功能的基础。

安卓提供了与这种设计模式合作的类，使我们能够以简单的方式创建丰富的导航和屏幕管理体验。这些类提供了各种功能，包括过渡效果以及一些熟悉用户界面隐喻。

# 通过滑动使导航变得有趣

许多应用程序包含用户可能想要浏览或翻阅的多个数据屏幕，以查看每个屏幕。例如，考虑一个列出书籍目录的应用程序，目录中的每本书出现在一个单独的屏幕上。书籍的屏幕包含图像、标题和描述，如下面的截图所示：

![通过滑动使导航变得有趣](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_05_01_NEW.jpg)

为了查看每本书的信息，用户需要移动到每个屏幕。我们可以在屏幕上放置一个下一个按钮和一个上一个按钮，但更自然的操作是用户使用他们的拇指或手指从显示的一侧滑动到另一侧，下一个包含书籍信息的屏幕就会像下面的截图所示那样滑入视野：

![通过滑动使导航变得有趣](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_05_02_NEW.jpg)

这创造了一个非常自然的导航体验，老实说，这比使用按钮更是一种有趣的浏览应用程序的方式。

## 实现滑动导航

实现滑动导航非常简单，碎片是其核心。每个屏幕都作为碎片派生类实现。每个屏幕可以是完全不同的碎片派生类，或者屏幕可以是具有不同数据的相同碎片派生类的实例。为了创建如前所示截图中的书籍浏览器应用，我们可以使用一个简单的碎片派生类，设置书籍图片、标题和描述。

关于碎片派生类（fragment derived class）有一点比较特别。在撰写本文时，管理滑动导航的类相对较新，仅在`android.support.v4.app`包中可用。因此，即使我们的应用目标是本地支持碎片的 Android 版本，我们创建的碎片派生类也必须继承自支持包版本的`Fragment`类，即`android.support.v4.app.Fragment`。碎片类的定义将类似于以下代码：

```java
import android.support.v4.app.Fragment;
public class BookFragment extends Fragment {
  // members elided for clarity
}
```

### 管理滑动碎片

展现代表应用屏幕的各个碎片需要一个适配器来管理每个碎片的创建和传递。Android 支持库包括两个提供此功能的类：`FragmentPagerAdapter`和`FragmentStatePagerAdapter`。

`FragmentPagerAdapter`类适用于只有少量碎片（fragments）的场景。一旦创建了给定碎片实例，它会被直接存储在`FragmentManager`类中，并且每次显示该碎片的页面时都会重新使用这个实例。当用户切换到另一个不同碎片时，会调用碎片的`onDestroyView`方法，但不会调用`onDestroy`方法。重要的是，我们只在碎片数量相对较少的情况下使用`FragmentPagerAdapter`类，因为我们应该假定一旦创建了碎片，只要`FragmentPagerAdapter`类存在，它就会一直存在。

`FragmentStatePagerAdapter`类适用于有大量碎片的情况，因为当碎片不再可见时，它们可能会被销毁。由`FragmentStatePagerAdapter`管理的碎片将始终调用其`onDestroyView`方法，并且也可能调用其`onDestroy`方法。调用`onDestroy`方法不一定会立即在用户滑动到另一个碎片时发生，它可能会根据设备可用资源的情况在稍后发生。`FragmentStatePagerAdapter`类让碎片有机会通过平台调用`onSaveInstanceState`方法来保存其状态。

`FragmentStatePagerAdapter`类能够丢弃和重新创建包含的片段，这使得它也适用于显示的片段列表可能发生变化的情况。实现可更新的`FragmentStatePagerAdapter`实例的细节超出了本书的范围，但可以在[`bit.ly/UpdateFragmentStatePagerAdapter`](http://bit.ly/UpdateFragmentStatePagerAdapter)找到一个示例。

要创建如前截图所示的书籍浏览器应用，我们将扩展`FragmentPagerAdapter`类，因为我们只会显示几本书。我们将我们的类命名为`BookPagerAdapter`，其声明如下面的代码所示：

```java
public class BookPagerAdapter extends FragmentPagerAdapter {
  // members elided for clarity
}
```

要实现我们的`BookPagerAdapter`类，我们只需要覆盖几个方法。主要的方法`getItem`负责返回每个片段实例。我们的`getItem`方法如下所示：

```java
public Fragment getItem(int idx) {

  // Store the argument values for this fragment
  Bundle arguments = new Bundle();
  arguments.putString(
      BookFragment.BOOK_TITLE, mCourseTitles[idx]);
  arguments.putString(
      BookFragment.BOOK_DESCRIPTIONS, mCourseDescriptions[idx]);
  arguments.putInt(
      BookFragment.TOP_IMAGE, mTopImageResourceIds[idx]);

  // Create the fragment instance and pass the arguments
  BookFragment bookFragment = new BookFragment();
  bookFragment.setArguments(arguments);

  // return the fragment instance
  return bookFragment;
}
```

当应用首次显示特定书籍的页面时，会调用`getItem`方法，并以名为`idx`的参数传递页面索引。在创建片段之前，我们从包含这些值的数组中检索书籍标题、描述和图像资源 ID，并将它们存储在`Bundle`实例中。然后，我们创建`BookFragment`类的实例，并将其与参数`Bundle`实例关联。最后，我们返回`BookFragment`的引用。当我们的`BookFragment`实例被显示时，它将访问参数`Bundle`实例中的值并将其显示出来。

我们现在必须覆盖另外两个方法：`getPageTitle`和`getCount`。`getPageTitle`方法返回在每片段上方的细条中可见的字符串。与`getItem`方法一样，`getPageTitle`方法接收正在显示的页面的索引。`getPageTitle`方法仅从包含页面标题简短版本的数组中返回一个值，如下面的代码所示：

```java
  public CharSequence getPageTitle(int idx) {
    return mCourseTitlesShort[idx];
  }
```

`getCount`方法负责返回我们将要显示的屏幕数量。我们可以简单地返回在`getPageTitle`方法中使用的数组的长度，如下面的代码所示：

```java
public int getCount() {
  return mCourseTitlesShort.length;
}
```

实现我们的`BookPagerAdapter`类处理了管理我们片段的代码。现在，我们只需要在我们的活动中放置适当的布局，并将其与适配器连接起来。

### 实现滑动用户界面

滑动用户界面行为和效果来自两个 Android 类：`ViewPager`和`PagerTitleStrip`。`ViewPager`类是主要的类。它管理用户交互，提供滑动动画效果，并与提供每个屏幕片段的适配器类合作。`PagerTitleStrip`类处理在每个片段上方的细标题栏的显示。从我们的`BookPagerAdapter`类的`getPageTitle`方法返回的字符串值显示在`PagerTitleStrip`实例中。

我们将为应用程序的活动创建一个名为`activity_main.xml`的布局资源文件，其中包含`ViewPager`和`PagerTitleStrip`类，如下面的 XML 布局所示：

```java
<android.support.v4.view.ViewPager

    android:id="@+id/pager"
    android:layout_width="match_parent"
    android:layout_height="match_parent">

  <android.support.v4.view.PagerTitleStrip
      android:id="@+id/pager_title_strip"
      android:layout_width="match_parent"
      android:layout_height="wrap_content"
      android:layout_gravity="top"
      android:background="#33b5e5"
      android:paddingBottom="4dp"
      android:paddingTop="4dp"
      android:textColor="#fff"/>

</android.support.v4.view.ViewPager>
```

我们的布局资源文件以`ViewPager`作为根节点，并设置为占据整个活动。`ViewPager`类的 ID 值为`pager`。`PagerTitleStrip`类被设置为填充`ViewPager`的整个宽度，并位于顶部。另外，我们也可以将`layout_gravity`属性设置为`bottom`，以将`PagerTitleStrip`定位在`ViewPager`类显示区域的底部。尽管技术上`layout_gravity`属性的其他值是有效的，但它们往往会出现问题。通常，我们希望将`layout_gravity`属性的选择限制为`top`或`bottom`。

我们已经完成了布局设计，并已经创建了管理应用内片段的适配器。现在我们准备声明我们的活动类，我们将其命名为`MainActivity`。类的声明如下所示：

```java
import android.support.v4.app.FragmentActivity;
import android.support.v4.view.ViewPager;

public class MainActivity extends FragmentActivity {
  BookPagerAdapter mBookPagerAdapter;
  ViewPager mViewPager;

  // other members elided for clarity
}
```

请注意，我们从支持库类`FragmentActvity`继承，而不是常规的`Activity`类。这是我们声明`BookFragment`类时讨论的同样问题。提供滑动行为的类在支持库中；因此，它们期望所有与片段相关的类都来自该库。我们的活动类包括`BookPagerAdapter`和`ViewPager`类的成员变量。

我们需要做的最后一件事是将我们的`BookPagerAdapter`类连接到`ViewPager`类。我们将在`onCreate`方法中这样做，如下所示：

```java
protected void onCreate(Bundle savedInstanceState) {
  super.onCreate(savedInstanceState);
  setContentView(R.layout.activity_main);

  mBookPagerAdapter = new BookPagerAdapter(
      getSupportFragmentManager(), this);

  mViewPager = (ViewPager) findViewById(R.id.pager);
  mViewPager.setAdapter(mBookPagerAdapter);
}
```

如我们所见，这里的工作相当简单。我们调用`setContentView`方法，并传入我们刚刚创建的`R.layout.activity_main`资源。当`setContentView`方法返回后，我们创建`BookPagerAdapter`实例，传入活动的`FragmentManager`实例和活动的`this`指针，以便我们的`BookPagerAdapter`可以使用它作为上下文。创建`BookPagerAdapter`后，我们使用活动类的`findViewById`方法获取我们用布局资源文件创建的`ViewPager`类的引用。最后，我们调用`ViewPager`实例的`setAdapter`方法，将`BookPagerAdapter`实例连接到我们的`ViewPager`实例。

现在我们已经准备好了一切。我们的书籍浏览器已经可以使用滑动导航让用户浏览我们的书籍列表。

### Android Studio 和滑动导航

如果我们使用 Android Studio，那么开始构建带有滑动导航的应用程序是很容易的。在**新建项目**向导中，在设置活动和布局名称的对话框里，选择**可滚动标签 + 滑动**作为**导航类型**，如下面的截图所示：

![Android Studio 和滑动导航](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_05_03.jpg)

生成的项目将包括一个布局资源文件，其中包含 `ViewPager` 和 `PagerTitleStrip`，以及 `FragmentPagerAdapter`、`Fragment` 和 `Activity` 派生类的存根代码。

# 使用 ActionBar 改进导航

从 API 级别 11（Android 3.0）开始，Android 从使用传统的菜单转而使用 ActionBar。ActionBar 提供的操作项是直接出现在 ActionBar 上的基于按钮的操作和当用户点击操作溢出按钮时出现在下拉列表中的基于菜单的操作的组合。以下屏幕截图显示了可用的 ActionBar 操作：

![使用 ActionBar 改进导航](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_05_04.jpg)

许多开发者没有意识到，基于按钮和菜单的操作只是 ActionBar 实际功能的冰山一角。现在，ActionBar 已成为许多与导航相关行为的核心点。其中两种行为直接与片段相关：标签导航和下拉导航。

### 注意事项

若要在针对 API 级别低于 11 的 Android 版本的应用程序中包含 ActionBar，请使用 Android 支持库中提供的 `ActionBarCompat` 类。有关 `ActionBarCompat` 类的更多信息，请访问 [`bit.ly/ActionBarCompat`](http://bit.ly/ActionBarCompat)。

## 通过标签随机导航

标签是一种有效的导航模型。它们被用户广泛理解，并使应用程序内屏幕之间的移动变得简单。与需要用户按顺序通过屏幕的滑动导航不同，标签导航允许用户按照自己喜欢的任何顺序从一个屏幕移动到另一个屏幕。自 Android 平台最初发布以来，就支持标签导航。历史上，实现标签导航的挑战在于它与其他导航模型无关，需要使用特殊的活动类和其他特定于标签的类。现在有了 ActionBar，这一切都改变了。现在，标签导航只是通用片段编程模型的另一种用途。

ActionBar 允许我们将一个片段派生类的实例与每个标签关联。以下屏幕截图显示了两个不同设备屏幕顶部的部分，ActionBar 显示了标签：

![通过标签随机导航](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_05_05.jpg)

请注意，ActionBar 会根据可用的屏幕空间自动调整标签的显示方式。在较窄的设备上，ActionBar 将标签放置在 ActionBar 的主体下方，而在具有更多水平屏幕空间的较宽设备上，标签直接出现在 ActionBar 的主体上。

### 管理标签选择

当涉及到实现标签导航时，ActionBar 处理所有繁重的工作。它绘制标签，指示当前选定的标签，甚至负责开始并提交片段事务。所有我们需要做的就是根据当前选定的标签处理哪个片段可见。为此，我们为每个标签提供了一个`ActionBar.TabListener`接口的实现。以下代码展示了实现该接口的类的声明：

```java
public class SimpleTabListener implements ActionBar.TabListener {
  boolean mFirstSelect = true;
  Fragment mFragment;

  public SimpleTabListener(Fragment fragment) {
    mFragment = fragment;
  }

  // Other members elided for clarity
}
```

我们的`TabListener`实现有两个成员变量。布尔成员变量`mFirstSelect`用于控制第一次由我们的`SimpleTabListener`类管理的片段被选定时的特殊处理。另一个成员变量`mFragment`保存了由`TabListener`实例管理的片段的引用，在`SimpleTabListener`构造函数中设置。

我们将实现的首个`TabListener`接口方法是`onTabSelected`方法。顾名思义，每次与此`TabListener`实例关联的标签被选定时，都会调用`onTabSelected`方法。如下代码所示实现了`onTabSelected`方法：

```java
public void onTabSelected(
    ActionBar.Tab tab, FragmentTransaction fragmentTransaction) {
  if (mFirstSelect) {
    fragmentTransaction.add(android.R.id.content, mFragment);
    mFirstSelect = false;
  }
  else
    fragmentTransaction.attach(mFragment);
}
```

`onTabSelected`方法接收两个参数。第一个参数是与我们的`TabListener`实现相关联的标签实例的引用。第二个参数是由 ActionBar 管理的`FragmentTransaction`实例。ActionBar 开始这个事务，并在`onTabSelected`返回后提交事务。

当`onTabSelected`方法首次被调用时，我们使用传递进来的`FragmentTransaction`实例，通过`add`方法将我们的片段添加到显示中。正如在前一章中讨论的，`add`方法的第一参数是我们希望放置片段的视图组 ID。就像我们自己管理`FragmentsTransaction`时一样，这可以是活动布局中的任何有效视图组。在之前的代码中，我们使用的是 Android 预定义的特殊 ID 值，`android.R.id.content`。`android.R.id.content` ID 值表示我们希望片段占据活动的整个内容区域，而不是放在活动内的特定视图组中。

我们只在标签首次选定时使用`add`方法；之后每次，我们都使用`FragmentTransaction`类的`attach`方法。我们稍后会进一步讨论这个问题。

我们将实现的下一个`TabListener`接口方法是`onTabUnselected`方法，如下代码所示：

```java
public void onTabUnselected(
    ActionBar.Tab tab, FragmentTransaction fragmentTransaction) {
  fragmentTransaction.detach(mFragment);
}
```

`onTabUnselected`方法接收与`onTabSelected`方法相同的参数。我们这个方法的实现很简单，只有一行代码，我们调用了`FragmentTransaction`类的`detach`方法。

`onTabUnselected`方法中的`detach`方法调用与`onTabSelected`方法中的`attach`方法调用协同工作。一旦碎片最初被添加到活动中，就像第一次显示碎片时在`onTabSelected`方法中所做的那样，我们可以随后调用`detach`方法来拆除碎片视图层次结构，但让碎片与活动关联。当我们再次在`onTabSelected`方法中调用`attach`方法时，下次用户选择该碎片的标签时，将在活动中原始添加碎片的位置重新构建碎片的视图层次结构。

这种调用`detach`和`attach`方法的技术使我们能够更有效地管理碎片。当我们调用`detach`方法时，会调用碎片的`onDestroyView`方法，但不会调用`onDestroy`方法。稍后当我们调用`attach`方法时，会调用碎片的`onCreateView`方法，但不会调用`onCreate`方法，因为不需要完全重新创建碎片，只需重新创建其视图层次结构即可。

我们需要注意一些可能导致混淆的方法名称。当碎片实例传递给`FragmentTransaction`类的`detach`方法时，并不会调用`Fragment`类的`onDetach`方法。这是因为`detach`方法拆除了碎片的视图层次结构，但让碎片与活动关联；碎片仍然处于附着状态。同样，当碎片实例传递给`FragmentTransaction`类的`attach`方法时，不会调用`Fragment`类的`onAttach`方法，因为碎片已经与活动关联。这确实有些令人困惑，但最终这归咎于 API 设计者选择了糟糕的方法名称，而不是技术上的不一致性。

`TabListener`接口的最后一个方法`onTabReselected`，在用户点击已经选中的标签的场景下被调用；换句话说，就是用户重新选择了同一个标签。在大多数情况下，这个方法可以留空，如下面的代码所示：

```java
public void onTabReselected(
  ActionBar.Tab tab, FragmentTransaction fragmentTransaction) { }
```

### 将碎片连接到标签

由于我们已经有了`TabListener`的实现，现在可以将碎片连接到标签。我们将在活动的`onCreate`方法中这样做，具体代码如下所示：

```java
protected void onCreate(Bundle savedInstanceState) {
  super.onCreate(savedInstanceState);

  // Put ActionBar in Tab mode
  ActionBar actionBar = getActionBar();
  actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_TABS);

  // Create the first tab
  Fragment firstFragment = new FirstFragment();
  ActionBar.TabListener firstListener =
      new SimpleTabListener(firstFragment);
  ActionBar.Tab firstTab = actionBar.newTab()
      .setText("First")
      .setTabListener(firstListener);
  actionBar.addTab(firstTab);

  // Create the second tab
  Fragment secondFragment = new SecondFragment();
  ActionBar.TabListener secondListener =
      new SimpleTabListener(secondFragment);
  ActionBar.Tab secondTab = actionBar.newTab()
      .setText("Second")
      .setTabListener(secondListener);
  actionBar.addTab(secondTab);
}
```

在我们的`onCreate`实现中，首先获取对 ActionBar 的引用，并将 ActionBar 设置为标签导航模式。这一步是必不可少的；如果没有这一步，我们添加的标签将永远不会显示。

对于第一个标签，我们创建将作为标签主体的片段。这可以是几乎任何从片段派生的类。然后我们将`TabListener`实现与片段关联。在片段和`TabListener`实现就位后，我们通过调用`newTab`方法创建一个新的`ActionBar.Tab`实例，然后设置将在标签中显示的文本，并将我们的`TabListener`实例与标签关联。最后，我们使用`addTab`方法将`ActionBar.Tab`实例添加到 ActionBar 中。然后我们对第二个标签重复这些步骤。

这样，我们的应用程序现在实现了标签导航。使用这种技术，我们能够利用片段的所有功能，并以与其他使用片段的方式一致的方式实现基于标签的导航。

我们`onCreate`方法实现中可能看起来不太寻常的一点是缺少了对`setContentView`方法的调用。在这种情况下，我们不需要将布局资源与活动关联，因为当我们在`onTabSelected`实现中调用`add`方法时，使用了特殊用途的`android.R.id.content`资源 ID。正如我们之前提到的，资源 ID `android.R.id.content`表示片段占据了整个内容区域。如果我们希望标签控制某个视图组内片段的显示，我们会用包含所需布局的资源调用`setContentView`。然后，我们会在调用`add`方法时使用该布局中视图组的 ID。

## 通过下拉列表导航提供直接访问

当应用只有少数可预测的屏幕时，标签导航工作得很好，但如果屏幕数量很多，它会很快变得杂乱。对于那些屏幕数量很多的应用，或者可能屏幕数量随时间变化的情况，下拉列表导航提供了一个比标签更好的解决方案。下拉列表导航在 ActionBar 上放置一个包含可用屏幕名称列表的下拉列表。当用户从列表中选择一个屏幕名称时，应用会立即显示相应的屏幕。

在 Android 上，这种导航模型最熟悉的用途可能是 Android 电子邮件应用，如下面的截图所示：

![通过下拉列表导航提供直接访问](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_05_06.jpg)

在 Android 电子邮件应用中，不同的电子邮件文件夹屏幕列表显示在下拉列表中。点击 ActionBar 会显示列表，然后从列表中选择屏幕名称会立即显示该屏幕。

在我们的应用中整合下拉列表导航非常简单。

### 管理片段选择

与标签导航不同，在 ActionBar 在管理从一个片段到另一个片段的过渡中扮演非常活跃的角色，而在下拉列表导航中，ActionBar 采取了更为放手的方法。基本上，ActionBar 只是通知应用选择已更改，而将切换片段的细节留给应用处理。为了处理这个通知，我们需要提供一个`ActionBar.OnNavigationListener`接口的实现。实现声明如下面的代码所示：

```java
public class SimpleNavigationListener
    implements ActionBar.OnNavigationListener {
  FragmentManager mFragmentManager;

  public SimpleNavigationListener(FragmentManager fm) {
    mFragmentManager = fm;
  }

  // Other members elided for clarity
}
```

我们的`ActionBar.OnNavigationListener`实现有一个成员变量`mFragmentManager`，用于保存对 activity 的`FragmentManager`实例的引用。`FragmentManager`引用在构造函数中传递给我们的类。

与标签导航中每个标签实例都由一个单独的`TabListener`实例管理不同，在下拉列表导航中，一个单独的`OnNavigationListener`实现处理所有选择。每次选择更改时都会调用`OnNavigationListener`接口的唯一方法`onNavigationItemSelected`，并负责处理显示适当的片段，如下面的实现所示：

```java
public boolean onNavigationItemSelected(
    int itemPosition, long itemId) {
  Fragment fragment = null;

  // Create an instance of the appropriate Fragment
  switch (itemPosition) {
    case 0:
      fragment = new FirstFragment();
      break;
    case 1:
      fragment = new SecondFragment();
      break;
    case 2:
      fragment = new ThirdFragment();
      break;
  }

  // Replace the currently visible fragment with the new one
  if (fragment != null) {
    FragmentTransaction ft = mFragmentManager.beginTransaction();
    ft.replace(android.R.id.content, fragment);
    ft.commit();
  }

  return true;
}
```

我们接收基于零的选中项索引作为第一个参数`itemPosition`。我们将从一个简单的`String`数组中填充屏幕名称列表，所以第二个参数`itemId`对我们没有价值。如果我们使用更结构化的数据源，`itemId`参数将包含选中项的 ID。

使用`switch`语句，我们创建适当的片段派生类的实例。一旦我们有了片段实例，我们就会用刚刚创建的片段替换当前可见的片段。我们再次使用布局资源 ID `android.R.id.content`，表示片段占据了 activity 整个内容区域。如果我们愿意，也可以使用 activity 布局中视图组的 ID 值，就像标签导航一样。

请注意，在我们的代码中，我们显式地创建并提交了`FragmentTransaction`实例。这是与标签导航管理方式的另一个重要区别；我们需要负责所有细节。检查局部变量`fragment`不为 null 只是一个健全性检查。只要我们为用户显示的选择不超过三个值，`fragment`变量就永远不会为 null。

返回`true`的方法值仅表示我们已经处理了该事件。

### 提供导航选择

我们现在需要向 ActionBar 提供显示导航选择列表所需的信息。我们是在 activity 的`onCreate`方法中完成这一操作，如下面的代码所示：

```java
protected void onCreate(Bundle savedInstanceState) {
  super.onCreate(savedInstanceState);

  // Put the ActionBar in the right mode and clear any clutter
  ActionBar actionBar = getActionBar();
  actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_LIST);
  actionBar.setDisplayShowTitleEnabled(false);

  // Get the list of display values and wrap in an adapter
  String[] screenNames =getResources().getStringArray(R.array.screen_names);
  ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,android.R.layout.simple_list_item_1, screenNames);

  // Create the Listener and associate with the ActionBar
  ActionBar.OnNavigationListener listener =new SimpleNavigationListener(getFragmentManager());
  actionBar.setListNavigationCallbacks(adapter, listener);
}
```

设置下拉列表导航的第一步是使用`setNavigationMode`方法的调用将 ActionBar 设置为列表导航模式。包含屏幕选择的下拉列表直接出现在 ActionBar 上，如果 ActionBar 试图同时显示下拉列表和活动标题文本，这可能会出现问题。为了给列表腾出空间，我们使用`setDisplayShowTitleEnabled`方法并传递`false`值，这样标题就不会显示。

我们从数组资源中检索显示值列表，这是一个常规的`String`数组。我们将`String`数组包装在`ArrayAdapter`类的一个实例中，就像我们计划将`String`数组与在活动布局定义中出现的标准`ListView`实例关联一样。`String`数组资源定义如下面的 XML 代码所示：

```java
<string-array name="screen_names">
  <item>First View</item>
  <item>Second View</item>
  <item>Third View</item>
</string-array>
```

然后，我们创建了一个之前定义的`SimpleNavigationListener`实例。最后，我们通过调用`setListNavigationCallbacks`方法来设置显示的屏幕名称列表和屏幕选择处理程序，从而将`ArrayAdapter`和`SimpleNavigationListener`实现与`ActionBar`关联。

这样我们就完成了下拉导航的完全实现。运行应用程序时，屏幕选择列表将如下截图所示出现。ActionBar 最初如下截图左侧所示，显示当前选定屏幕的名称。当用户点击当前选定的屏幕名称时，列表将展开，如下截图右侧所示，显示可用的屏幕名称列表。列表展开后，用户只需点击列表中想要跳转的屏幕名称，就可以轻松直接跳转到任何可用的屏幕。

![提供导航选择](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/crt-dyna-ui-andr-frag/img/3095_05_07.jpg)

### Android Studio 和下拉列表导航

如果我们使用的是 Android Studio，可以通过**新建项目**向导直接创建一个支持下拉列表导航的项目，方法是选择**Dropdown**作为**导航类型**，这与我们创建带有滑动导航的项目的方式类似。生成的项目将包含一个`ActionBar.OnNavigationListener`实现的存根以及活动中的代码，以将 ActionBar 设置为下拉列表导航模式，并将`ActionBar.OnNavigationListener`实现与 ActionBar 关联。

# 总结

片段是现代 Android 应用开发的基础，它允许我们在单个活动中显示多个应用程序屏幕。由于片段提供的灵活性，我们现在可以相对容易地将丰富的导航功能集成到我们的应用程序中。使用这些丰富的导航功能，我们可以创建更加动态的用户界面体验，使我们的应用程序更具吸引力，用户也会觉得使用起来更有趣。
