# Angular NativeScript 移动开发（四）

> 原文：[`zh.annas-archive.org/md5/289e6d84a31dea4e7c2b3cd2576adf55`](https://zh.annas-archive.org/md5/289e6d84a31dea4e7c2b3cd2576adf55)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：用 SASS 打磨

在上一章节中涵盖了一些关于 ngrx 状态管理的底层改进之后，现在终于是时候打磨这个应用，改善其整体外观和感觉了。样式的时间完全取决于您的开发流程，通常情况下，我们喜欢边开发边打磨。在本书中，我们选择避免通过 CSS 混合打磨功能开发，以保持概念更加专注。然而，现在我们在这里，我们对为我们的应用获得漂亮外观感到非常兴奋。

由于随着样式的增长，标准 CSS 可能变得难以维护，我们将集成 SASS 来帮助。事实上，我们将利用一个由 Todd Anglin 开发的社区插件，他是帮助创建 NativeScript 品牌名称的人。

在本章中，我们将涵盖以下主题：

+   将 SASS 集成到您的应用中

+   构建核心主题的 SASS 设置的最佳实践

+   构建可扩展的样式设置，以最大化 iOS 和 Android 之间的样式重用

+   使用字体图标，如*Font Awesome*，使用 nativescript-ngx-fonticon 插件

# 用 SASS 打磨

SASS 是世界上最成熟、稳定和强大的专业级 CSS 扩展语言... Sass 是 CSS 的扩展，为基本语言增添了力量和优雅。它允许您使用变量、嵌套规则、混合、内联导入等，所有这些都具有完全兼容 CSS 的语法。SASS 有助于保持大型样式表的良好组织，并使小型样式表快速运行起来。

+   http://sass-lang.com/documentation/file.SASS_REFERENCE.html

听起来不错吧？当然。

我们首先要安装由 Todd Anglin 发布的社区插件：

```ts
npm install nativescript-dev-sass --save-dev
```

这个插件将设置一个钩子，在构建应用之前自动将您的 SASS 编译为 CSS，因此您无需担心安装任何其他构建工具。

我们现在希望以一种特定的方式组织我们的 SASS 源文件，这种方式不仅有利于 iOS 和 Android 之间的共享样式的维护，还可以轻松地允许特定于平台的调整/覆盖。默认安装的核心主题（`nativescript-theme-core`）附带了一套完整的 SASS 源文件，这些文件已经组织得很好，可以帮助您轻松地在其基础上构建自定义的 SASS。

让我们从重命名以下开始：

+   `app.ios.css`改为`app.ios.**scss**`

+   `app.android.css`改为`app.android.**scss**`

然后是`app.ios.scss`的内容：

```ts
@import 'style/common';
@import 'style/ios-overrides';
```

以及对于`app.android.scss`：

```ts
@import 'style/common';
@import 'style/android-overrides';
```

现在，让我们创建带有各种部分 SASS 导入文件的`style`文件夹，以帮助我们的设置，从变量开始：

+   `style/_variables.scss`：

```ts
// baseline theme colors
@import '~nativescript-theme-core/scss/dark';
// define our own variables or simply override those from the light set here...
```

实际上，您可以基于许多不同的皮肤/颜色来设置应用程序的样式表。查看文档中的以下部分，了解可用的选项：[`docs.nativescript.org/ui/theme#color-schemes`](http://docs.nativescript.org/ui/theme#color-schemes)。对于我们的应用程序，我们将以*dark*皮肤为基础设置颜色。

现在，创建共享的 SASS 文件，这是大部分共享样式的地方。实际上，我们将把我们在`common.css`文件中定义的所有内容放在这里（然后，删除我们以前拥有的`common.css`文件）：

+   `style/_common.scss`：

```ts
// customized variables
@import 'variables';
// theme standard rulesets
@import '~nativescript-theme-core/scss/index';
// all the styles we had created previously in common.css migrated into here:

.action-bar {
  background-color:#101B2E; // we can now convert this to a SASS variable
}

Page {
  background-color:#101B2E; // we can now convert this to a SASS variable
}

ListView { 
  separator-color: transparent; 
}

.track-name-float {
  color: RGBA(136, 135, 3, .5); // we can now convert this to a SASS variable
}

.slider.fader {
  background-color: #000; // we could actually use $black from core theme now
}

.list-group .muted {
  opacity:.2;
}

```

这使用了我们刚刚创建的变量文件，使我们能够使用核心主题的基线变量，并对颜色进行自定义调整。

现在，如果需要，创建 Android 覆盖文件：

+   `styles/_android-overrides.scss`：

```ts
@import '~nativescript-theme-core/scss/platforms/index.android';
// our custom Android overrides can go here if needed...
```

这从核心主题导入了 Android 覆盖，同时仍然允许我们应用自定义覆盖（如果需要）。

我们现在可以为 iOS 执行相同的操作：

+   `styles/_ios-overrides.scss`：

```ts
@import '~nativescript-theme-core/scss/platforms/index.ios';
// our custom iOS overrides can go here if needed...
```

最后，我们现在可以将任何特定于组件的`.css`文件转换为`**.scss**`。我们有一个组件使用其自定义的样式，`record.component.css`。只需将其重命名为`**.scss**`。NativeScript SASS 插件将自动编译它找到的任何嵌套`.scss`文件。

您可能还想做两件事：

除了在 IDE 中隐藏`.css`和`.js`文件之外，还要从 git 中忽略所有`*.css`文件。

您不希望在将来与其他开发人员发生合并冲突，因为每次构建应用程序时，您的`.css`文件都将通过 SASS 编译生成。

将以下内容添加到您的`.gitignore`文件中：

```ts
*.js
*.map
*.css
hooks
lib
node_modules
/platforms
```

然后，要在 VS Code 中隐藏`.js`和`.css`文件，我们可以这样做：

```ts
{
  "files.exclude": {
    "**/app/**/*.css": {
 "when": "$(basename).scss"
 },
 "**/app/**/*.js": {
 "when": "$(basename).ts"
 },
    "**/hooks": true,
    "**/node_modules": true,
    "platforms": true
  }
}
```

现在结构应该如下所示的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00048.jpeg)

# 使用 nativescript-ngx-fonticon 插件使用字体图标

确实很好将所有那些无聊的标签按钮替换为漂亮清晰的图标，所以让我们这样做。NativeScript 提供了对使用 Unicode 值在按钮、标签等文本属性上支持自定义字体图标的支持。然而，使用 Angular，我们可以利用另一个巧妙的插件，它将提供一个很好的管道，使我们可以使用字体名称以方便使用和清晰度。

安装以下插件：

```ts
npm install nativescript-ngx-fonticon --save
```

对于这个应用程序，我们将使用多功能的 font-awesome 图标，所以让我们从官方网站这里下载该软件包：[`fontawesome.io/`](http://fontawesome.io/)。

在其中，我们将找到我们需要的字体文件和 css。我们想首先将`fontawesome-webfont.ttf`文件复制到我们将在`app`文件夹中创建的`new fonts`文件夹中。当构建应用程序时，NativeScript 将在该文件夹中查找任何自定义字体文件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00049.jpeg)

我们现在还想将`css/font-awesome.css`文件复制到我们的应用程序文件夹中。我们可以将其放在文件夹的根目录或子文件夹中。我们将创建一个`assets`文件夹来存放这个以及将来可能的其他类似项目。

但是，我们需要稍微修改这个`.css`文件。`nativescript-ngx-fonticon`插件只能使用字体类名，不需要 font-awesome 提供的任何实用类。因此，我们需要修改它，删除顶部的大部分内容，使其看起来像这样：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00050.jpeg)

您可以在以下视频中了解更多信息：[`www.youtube.com/watch?v=qb2sk0XXQDw`](https://www.youtube.com/watch?v=qb2sk0XXQDw)。

我们还设置了 git 来忽略以前的所有`*.css`文件；但是，我们不想忽略以下文件：

```ts
*.js
*.map
*.css
!app/assets/font-awesome.css
hooks
lib
node_modules
/platforms
```

现在，我们准备设置插件。由于这应该是我们应用程序核心设置的一部分，我们将修改`app/modules/core/core.module`以配置我们的插件：

```ts
...
import { TNSFontIconModule } from 'nativescript-ngx-fonticon';
...
@NgModule({
  imports: [
    ...MODULES,
    // font icons
    TNSFontIconModule.forRoot({
 'fa': './assets/font-awesome.css'
 }),
    ...
  ],
  ...
})
export class CoreModule {
```

由于该模块依赖于`TNSFontIconService`，让我们修改我们的根组件以注入它，确保 Angular 的 DI 为我们实例化单例以在整个应用程序中使用。

`app/app.component.ts`：

```ts
...
// libs
import { TNSFontIconService } from 'nativescript-ngx-fonticon';

@Component({
  moduleId: module.id,
  selector: 'my-app',
  templateUrl: 'app.component.html'
})
export class AppComponent {

  constructor(private fontIconService: TNSFontIconService) {
    ...
```

接下来，我们要确保`fonticon`管道对任何视图组件都是可访问的，所以让我们在`SharedModule`的`app/modules/shared/shared.module.ts`中导入和导出该模块：

```ts
...
// libs
import { TNSFontIconModule } from 'nativescript-ngx-fonticon';
...
@NgModule({
  imports: [
    NativeScriptModule, 
    NativeScriptRouterModule, 
    NativeScriptFormsModule, 
    TNSFontIconModule
  ],
  ...
  exports: [
    ...
    TNSFontIconModule, ...PIPES  ]
})
export class SharedModule {}
```

最后，我们需要一个类来指定哪些组件应该使用 font-awesome 来渲染自己。由于这个类将在 iOS/Android 上共享，所以在`app/style/_common.scss`中进行修改，如下所示：

```ts
// customized variables
@import 'variables';
// theme standard rulesets
@import '~nativescript-theme-core/scss/index';

.fa {
 font-family: 'FontAwesome', fontawesome-webfont;
 font-size: 25;
}
```

我们定义两种字体系列的原因是因为 iOS 和 Android 之间的差异。Android 使用文件名作为字体系列（在这种情况下是`fontawesome-webfont.ttf`）。而 iOS 使用实际的字体名称；示例可以在[`github.com/FortAwesome/Font-Awesome/blob/master/css/font-awesome.css#L8`](https://github.com/FortAwesome/Font-Awesome/blob/master/css/font-awesome.css#L8)找到。如果你愿意，你可以将字体文件重命名为`FontAwesome.ttf`，然后只使用`font-family: FontAwesome`。你可以在[`fluentreports.com/blog/?p=176`](http://fluentreports.com/blog/?p=176)了解更多信息。

现在，让我们尝试一下在我们的应用中渲染图标的新功能。打开`app/modules/mixer/components/mix-list.component.html`：

```ts
<ActionBar title="Compositions" class="action-bar">
  <ActionItem (tap)="add()" ios.position="right">
    <Button [text]="'fa-plus' | fonticon" class="fa action-item"></Button>
  </ActionItem>
</ActionBar>
<ListView [items]="(mixer$ | async)?.compositions | orderBy: 'order'" class="list-group">
  <ng-template let-composition="item">
    <GridLayout rows="auto" columns="100,*,auto" class="list-group-item">
      <Button [text]="'fa-pencil' | fonticon" (tap)="edit(composition)" 
        row="0" col="0" class="fa"></Button>
      <Label [text]="composition.name" (tap)="select(composition)" 
        row="0" col="1" class="h2"></Label>
      <Label [text]="composition.tracks.length" 
        row="0" col="2" class="text-right"> </Label>
    </GridLayout>
  </ng-template>
</ListView>
```

让我们也调整一下我们`ListView`的背景颜色，暂时设为黑色。我们甚至可以在`app/style/_common.scss`中使用核心主题的预定义变量来使用 SASS：

```ts
.list-group {
  background-color: $black;

  .muted {
    opacity:.2;
  }
}
```

！[](../images/00051.jpeg)我们的组合列表视图现在开始看起来相当不错。

让我们继续，在`app/modules/player/components/track-list/track-list.component.html`中为我们的曲目列表视图添加一些图标：

```ts
<ListView #listview [items]="tracks | orderBy: 'order'"   class="list-group" [itemTemplateSelector]="templateSelector">
  <ng-template let-track="item" nsTemplateKey="default">
    <GridLayout rows="auto" columns="**60**,*,**30**" 
      class="list-group-item" [class.muted]="track.mute">
      <Button **[text]="'fa-circle' | fonticon"** 
        (tap)="record(track)" row="0" col="0" **class="fa c-ruby"**></Button>
      <Label [text]="track.name" row="0" col="1" class="h2"></Label>
      <Label **[text]="(track.mute ? 'fa-volume-off' : 'fa-volume-up') | fonticon"**
        row="0" col="2" class="fa" **(tap)="track.mute=!track.mute"**></Label>
    </GridLayout>
  </ng-template>
  ...
```

我们用一个标签来替换了之前的开关，设计成可以切换两种不同的图标。我们还利用了核心主题的便利颜色类，比如 c-ruby。

我们还可以通过一些图标来改进我们的自定义`ActionBar`模板：

```ts
<ActionBar [title]="title" class="action-bar">
  <ActionItem nsRouterLink="/mixer/home">
    <Button [text]="'fa-list-ul' | fonticon" class="fa action-item"></Button>
  </ActionItem>
  <ActionItem (tap)="toggleList()" ios.position="right">
    <Button [text]="((uiState$ | async)?.trackListViewType == 'default' ? 'fa-sliders' : 'fa-list') | fonticon" class="fa action-item"></Button>
  </ActionItem>
  <ActionItem (tap)="recordAction.next()" ios.position="right">
    <Button [text]="'fa-circle' | fonticon" class="fa c-ruby action-item"></Button>
  </ActionItem>
</ActionBar>
```

现在我们可以在`app/modules/player/components/player-controls/player-controls.component.html`中对播放器控件进行样式设置：

```ts
<StackLayout row="1" col="0" class="controls">
  <shuttle-slider></shuttle-slider>
  <Button [text]="((playerState$ | async)?.player?.playing ? 'fa-pause' : 'fa-play') | fonticon" (tap)="togglePlay()" class="fa c-white t-30"></Button>
</StackLayout>
```

我们将利用核心主题中更多的辅助类。`c-white`类将我们的图标变为白色，`t-30`设置了`font-size: 30`。后者是`text-30`的缩写，另一个是`color-white`。

让我们来看一下：

！[](../images/00052.jpeg)

一些样式上的修饰确实可以展现出你的应用的个性。让我们再次在`app/modules/recorder/components/record.component.html`中使用刷子：

```ts
<ActionBar title="Record" icon="" class="action-bar">
  <NavigationButton visibility="collapsed"></NavigationButton>
  <ActionItem text="Cancel" ios.systemIcon="1" (tap)="cancel()"></ActionItem>
</ActionBar>
<FlexboxLayout class="record">
  <GridLayout rows="auto" columns="auto,*,auto" class="p-10" [visibility]="isModal ? 'visible' : 'collapsed'">
    <Button [text]="'fa-times' | fonticon" (tap)="cancel()" row="0" col="0" class="fa c-white"></Button>
  </GridLayout>
  <Waveform class="waveform"
    [model]="recorderService.model" 
    type="mic" 
    plotColor="yellow" 
    fill="false" 
    mirror="true" 
    plotType="buffer">
  </Waveform>
  <StackLayout class="p-5">
    <FlexboxLayout class="controls">
      <Button [text]="'fa-backward' | fonticon" class="fa text-center" (tap)="recorderService.rewind()" [isEnabled]="state == recordState.readyToPlay || state == recordState.playing"></Button>
      <Button [text]="recordBtn | fonticon" class="fa record-btn text-center" (tap)="recorderService.toggleRecord()" [isEnabled]="state != recordState.playing" [class.is-recording]="state == recordState.recording"></Button>
      <Button [text]="playBtn | fonticon" class="fa text-center" (tap)="recorderService.togglePlay()" [isEnabled]="state == recordState.readyToPlay || state == recordState.playing"></Button>
    </FlexboxLayout>
    <FlexboxLayout class="controls bottom" [class.recording]="state == recordState.recording">
      <Button [text]="'fa-check' | fonticon" class="fa" [class.save-ready]="state == recordState.readyToPlay" [isEnabled]="state == recordState.readyToPlay" (tap)="recorderService.save()"></Button>
    </FlexboxLayout>
  </StackLayout>
</FlexboxLayout>
```

现在我们可以调整我们的组件类来处理`recordBtn`和`playBtn`了：

```ts
...
export class RecordComponent implements OnInit, OnDestroy { 
  ...
  public recordBtn: string = 'fa-circle';
 public playBtn: string = 'fa-play';
```

然后，为了将所有内容绘制到位，我们可以将这些内容添加到我们的`app/modules/recorder/components/record.component.scss`中：

```ts
@import '../../../style/variables';

.record {
  background-color: $slate;
  flex-direction: column;
  justify-content: space-around;
  align-items: stretch;
  align-content: center;
}

.record .waveform {
  background-color: transparent;
  order: 1;
  flex-grow: 1;
}

.controls {
  width: 100%;
  height: 200;
  flex-direction: row;
  flex-wrap: nowrap;
  justify-content: center;
  align-items: center;
  align-content: center;

  .fa {
    font-size: 40;
    color: $white;

    &.record-btn {
      font-size: 70;
      color: $ruby;
      margin: 0 50 0 50;

      &.is-recording {
        color: $white;
      }
    }
  }
}

.controls.bottom {
  height: 90;
  justify-content: flex-end;
}

.controls.bottom.recording {
  background-color: #B0342D;
}

.controls.bottom .fa {
  border-radius: 60;
  font-size: 30;
  height: 62;
  width: 62;
  padding: 2;
  margin: 0 10 0 0;
}

.controls.bottom .fa.save-ready {
  background-color: #42B03D;
}

.controls .btn {
  color: #fff;
}

.controls .btn[isEnabled=false] {
  background-color: transparent;
  color: #777;
}
```

通过这种修饰，我们现在有了以下的截图：

！[](../images/00053.jpeg)

# 最后的修饰

让我们使用颜色来最终确定我们初始应用的样式。现在是改变`ActionBar`中使用的基本颜色，以提供我们想要的整体感觉的时候了。让我们从在`app/style/_variables.scss`中定义一些变量开始：

```ts
// baseline theme colors
@import '~nativescript-theme-core/scss/dark';

$slate: #150e0c;

// page
$background: $black;
// action-bar
$ab-background: $black;
```

通过这些少量的改变，我们给我们的应用赋予了不同的（客观上更时尚）氛围：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00054.jpeg)

# 总结

在本章中，我们终于能够为应用的外观添加一些精美的修饰。我们成功安装了`nativescript-dev-sass`插件，它在保持清晰的样式处理方法的同时，为我们的 CSS 添加了编译步骤。了解如何最好地利用核心主题的 SASS，并进行适当的文件组织，是获得灵活基础的关键。将本章介绍的概念应用到实践中，并告诉我们它们如何帮助您实现所需的样式目标；我们很乐意听到您的见解！

我们还学习了如何使用`nativescript-ngx-fonticon`插件，在整个应用中利用字体图标。这有助于用简洁的图标视觉清理笨重的文本标签。

在下一章中，我们将看看如何对一些关键功能进行单元测试，以未来保护我们应用的代码库免受新功能集成可能引入的回归。测试来拯救！


# 第十二章：单元测试

让我们从测试开始这一章；大多数人认为测试很无聊。猜猜，他们大多是对的！测试可以很有趣，因为你可以尝试并破坏你的代码，但有时也可能是乏味的工作。然而，它可以帮助你在客户之前捕捉到错误，并且作为一个奖励，它可以防止你多次出现相同的错误。你的声誉对你的客户或顾客来说值多少？一点点乏味的工作可能意味着一个三 A 级的应用和一个平庸的应用之间的差别。

在这一章中，我们将涵盖以下主题：

+   Angular 测试框架

+   NativeScript 测试框架

+   如何使用 Jasmine 编写测试

+   如何运行 Karma 测试

# 单元测试

单元测试用于测试应用程序代码功能的小部分是否正确。这也允许我们验证功能在重构代码和/或添加新功能时是否继续按预期工作。NativeScript 和 Angular 都提供单元测试框架。我们将探讨两种类型的单元测试，因为它们都有优缺点。

随时开发测试是好的。然而，最好是在项目代码开发的同时开发它们。当你的头脑还在新功能、修改和你刚刚添加的所有新代码上时，你会更加清晰。在我们的情况下，因为我们在整本书中介绍了许多新概念，我们没有遵循最佳实践，因为这样会使书变得更加复杂。因此，尽管后期添加测试是好的，但在添加新代码之前或同时添加它们被认为是最佳实践。

# Angular 测试

我们将要介绍的第一种单元测试是 Angular 单元测试。它基于 Karma（[`karma-runner.github.io/`](https://karma-runner.github.io/)）和 Jasmine（[`github.com/pivotal/jasmine`](http://github.com/pivotal/jasmine)）。Karma 是一个功能齐全的测试运行器，由 Angular 团队开发。当团队在实现 Angular 时，他们遇到了一些问题，比如如何测试 Angular，所以他们构建了 Karma。Karma 最终成为了行业标准的多用途测试运行器。Jasmine 是一个开源测试框架，实现了许多测试构造，帮助您轻松进行所有测试。它的历史比 Karma 长得多。因为在 Karma 之前很多人都在使用它，所以它成为了 Angular 社区的默认测试库。您可以自由选择其他框架，比如 Mocha、Chia，甚至您自己的自制测试框架。但是，由于几乎您在 Angular 社区看到的所有东西都是基于 Jasmine 的，我们也会使用它。

让我们为 NativeScript 中的 Angular 测试安装你需要的部分：

```ts
npm install jasmine-core karma karma-jasmine karma-chrome-launcher --save-dev
npm install @types/jasmine karma-browserify browserify watchify --save-dev
```

您还应该在全局安装 Karma，特别是在 Windows 上。但是，在其他平台上这样做也很有帮助，这样您只需输入`karma`就可以运行。为了做到这一点，请输入以下命令：

```ts
npm -g install karma
```

如果您没有全局安装 TypeScript，您无法只需输入`tsc`就进行构建，您应该全局安装它。在运行任何测试之前，您必须将您的 TypeScript 转译为 JavaScript。要全局安装 TypeScript，请输入以下命令：

```ts
npm -g install typescript
```

Karma 被设计为在浏览器中运行测试；然而，NativeScript 代码根本不在浏览器中运行。因此，我们必须以一些不同的方式来使标准的 Karma 测试系统与一些 NativeScript 应用程序代码一起运行。通常的 Angular 特定的 Karma 配置在大多数情况下都不起作用。如果您要在 Web 端进行任何 Angular 工作，您应该查看标准的 Angular 测试快速入门项目（[`github.com/angular/quickstart/`](https://github.com/angular/quickstart/)）。该项目将为在浏览器中运行的传统 Angular 应用程序设置好一切。

然而，在我们的情况下，因为我们使用的是 NativeScript Angular，我们将需要一个完全定制的`Karma.conf.js`文件。我们已经在 git 存储库中包含了自定义配置文件，或者你可以从这里输入。将这个文件保存为`Karma.ang.conf.js`。我们给出了一个不同的配置名称，因为我们稍后讨论的 NativeScript 测试将使用默认的`Karma.conf.js`名称。

```ts
module.exports = function(config) {
   config.set({
     // Enable Jasmine (Testing)
     frameworks: ['jasmine', 'browserify'],

     plugins: [
       require('karma-jasmine'),
       require('karma-chrome-launcher'),
       require('karma-browserify')
    ], 

    files: [ 'app/**/*.spec.js' ],

    preprocessors: {
       'app/**/*.js': ['browserify']
    },

    reporters: ['progress'],

    browsers: ['Chrome'], 
 });
};
```

这个配置设置了 Karma 将使用 Jasmine、Browserify 和 Chrome 来运行所有的测试。由于 Karma 和 Angular 最初是为浏览器设计的，所有的测试仍然必须在浏览器中运行。这是 Angular 测试系统在进行 NativeScript 代码时的主要缺点。它不支持任何 NativeScript 特定的代码。因此，这种类型的测试最好在数据模型文件和/或任何没有 NativeScript 特定代码的代码上进行，不幸的是，在你的一些应用程序中可能没有太多的代码。然而，如果你同时使用相同的代码库进行 NativeScript 和 Web 应用程序开发，那么你应该有很多代码可以通过标准的 Angular 测试框架运行。

对于 Angular 测试，你将创建 Jasmine 规范文件，它们都以`.spec.ts`结尾。我们必须在与你正在测试的代码相同的目录中创建这些文件。因此，让我们试着创建一个新的规范文件进行测试。由于这种类型的单元测试不允许你使用任何 NativeScript 代码，我选择了一个随机的模型文件来展示这种类型的单元测试有多容易。让我们在`app/modules/shared/models`文件夹中创建一个名为`track.model.spec.ts`的文件；这个文件将用于测试同一文件夹中的`track.model.ts`文件。这是我们的测试代码：

```ts
// This disables a issue in TypeScript 2.2+ that affects testing
// So this line is highly recommend to be added to all .spec.ts files
export = 0;

// Import our model file (This is what we are going to test)
// You can import ANY files you need
import {TrackModel} from './track.model';

// We use describe to describe what this test set is going to be
// You can have multiple describes in a testing file.
describe('app/modules/shared/models/TrackModel', () => {
  // Define whatever variables you need
  let trackModel: TrackModel;

  // This runs before each "it" function runs, so we can 
  // configure anything we need to for the actual test
  // There is an afterEach for running code after each test
  // If you need tear down code
  beforeEach( () => {
    // Create a new TrackModel class
    trackModel = new TrackModel({id: 1,
       filepath: 'Somewhere',
       name: 'in Cyberspace',
       order: 10,
       volume: 5,
       mute: false,
       model: 'My Model'});
  });

  // Lets run the first test. It makes sure our model is allocated
  // the beforeEach ran before this test, meaning it is defined.
  // This is a good test to make sure everything is working properly.
  it( "Model is defined", () => {
    expect(trackModel).toBeDefined();
  });

  // Make sure that the values we get OUT of the model actually
  // match what default values we put in to the model
  it ("Model to be configured correctly", () => {
    expect(trackModel.id).toBe(1);
    expect(trackModel.filepath).toBe('Somewhere' );
    expect(trackModel.name).toBe('in Cyberspace');
    expect(trackModel.order).toBe(10);
    expect(trackModel.model).toBe('My Model');
  });

  // Verify that the mute functionality actually works
  it ('Verify mute', () => {
    trackModel.mute = true;
    expect(trackModel.mute).toBe(true);
    expect(trackModel.volume).toBe(0);
    trackModel.mute = false;
    expect(trackModel.volume).toBe(5);
  });

  // Verify the volume functionality actually works
  it ('Verify Volume', () => {
    trackModel.mute = true;
    expect(trackModel.volume).toBe(0);
    trackModel.volume = 6;
    expect(trackModel.volume).toBe(6);
    expect(trackModel.mute).toBe(false);
  });
}); 
```

所以，让我们来分解一下。第一行修复了在浏览器中测试使用模块的 TypeScript 构建文件的问题。正如我在注释中指出的，这应该添加到所有的`spec.ts`文件中。接下来的一行是我们加载将要测试的模型；你可以在这里导入任何你需要的文件，包括 Angular 库。

记住，`.spec.js`文件只是一个普通的 TypeScript 文件；唯一的区别是它可以访问 Jasmine 全局函数，并在浏览器中运行。因此，你所有正常的 TypeScript 代码都会正常工作。

以下是我们开始实际测试框架的地方。这是一个 Jasmine 函数，用于创建一个测试。Jasmine 使用`describe`函数来开始一组测试。Describe 有两个参数：要打印的文本描述，然后是要运行的实际函数。因此，我们基本上输入我们正在测试的模型的名称，然后创建函数。在每个`describe`函数内，我们可以添加尽可能多的`it`函数。每个`it`用于一组测试。如果需要，还可以有多个`describes`。

因此，在我们的测试中，我们有四个单独的测试组；第一个只是为了验证一切是否正确。它只是确保我们的模型被正确定义。因此，我们只是使用 Jasmine 的`expect`命令来测试使用`.toBeDefined()`函数创建的有效对象。简单吧？

接下来的测试集试图确保默认值从`beforeEach`函数正确设置。正如你所看到的，我们再次使用`expect`命令和`.toBe(value)`函数。这实际上是非常推荐的；看起来设置的值应该与读取的值匹配，但你要把你的模块当作黑匣子。验证所有的输入和输出，确保它确实是以你设置的方式设置的。因此，即使我们知道我们将 ID 设置为 1，我们仍在验证当我们获取 ID 时，它仍然等于 1。

第三个测试函数开始测试静音功能，最后一个测试音量功能。请注意，*静音*和*音量*都有几种状态和/或影响多个变量。任何超出简单赋值的东西都应该通过你所知道的每一个状态进行测试，无论是有效的还是无效的，如果可能的话。在我们的情况下，我们注意到静音会影响音量，反之亦然。因此，我们验证当一个发生变化时，另一个也随之变化。这被用作合同，以确保，即使在将来这个类发生变化，它在外部仍然保持不变，或者我们的测试将会失败。在这种情况下，这更像是一个棕色盒；我们知道静音的副作用，并且我们依赖于应用中的这个副作用，因此我们将测试这个副作用，以确保它永远不会改变。

# 运行测试

现在，让我们通过输入`tsc`来创建转译后的 JS 文件，并运行以下命令来运行测试：

```ts
 karma start karma.ang.conf.js 
```

卡尔玛将找到所有的`.spec.js`文件，然后在您的 Chrome 浏览器上运行所有这些文件，测试您在每个`.spec.js`文件中定义的所有功能。

# 意外的测试失败

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00055.jpeg)

现在很有趣的是，我们的一个测试实际上失败了；`TrackModel Creation Verify mute FAILED`和**`Expected 1 to be 5.`**。这个失败并不是预先计划好的；实际上，这是一个真正的边缘情况，我们之所以发现它，是因为我们开始使用单元测试。如果你想快速查看代码，这里是`TrackModel.ts`代码，只显示相关的例程：

```ts
export class TrackModel implements ITrack { 
 private _volume: number = 1;
 private _mute: boolean;
 private _origVolume: number;
 constructor(model?: ITrack) {
   if (model) {
    for (let key in model) {
      this[key] = model[key];
    }
   }
 }

 public set mute(value: boolean) {
   value = typeof value === 'undefined' ? false : value;
   this._mute = value;
   if (this._mute) {
     this._origVolume = this._volume;
     this.volume = 0;
   } else {
     this.volume = this._origVolume;
   }
 }

 public set volume(value: number) {
   value = typeof value === 'undefined' ? 1 : value;
   this._volume = value;
   if (this._volume > 0 && this._mute) {
     this._origVolume = this._volume;
     this._mute = false;
   }
 }
}
```

现在，我会给你几分钟时间来查看前面的测试代码和这段代码，看看你能否发现测试失败的原因。

好的，我明白了，你回来了；你看到边缘情况在哪里了吗？如果你不能很快找到它，不要感到难过；我也花了几分钟才弄清楚为什么它失败了。

首先，看看错误消息；它说`Verify Mute FAILED`，这意味着我们的静音测试失败了。然后，我们在测试静音功能的`it`函数中放置了`Verify mute`。第二个线索是错误，`Expected 1 to be 5`。所以，我们期望某物是 5，但实际上是 1。所以，这个特定的测试和这行代码在测试中失败了：

```ts
 it ('Verify mute', () => {
     expect(trackModel.volume).toBe(5);
 });
```

# 为什么它失败了？

让我们从测试初始化`beforeEach`开始；你会看到``mute: false``。接下来，让我们看一下构造函数；它基本上执行`this.mute = false`，然后静音设置器沿着它的`else`路径运行，即`this.volume = this._origVolume`。猜猜看？`this._origVolume`还没有被设置，所以它设置`this.volume = undefined`。现在看看音量例程；新的音量是`undefined`，它被设置为`1`，这覆盖了我们原来设置的 5。所以，测试`Expected 1 to be 5.`失败了。

有趣的边缘情况；如果我们在测试属性初始化时没有将`mute`设置为`false`，这种情况就不会发生。然而，这是我们应该测试的东西，因为也许在应用程序的某个版本中，我们会存储静音值，并在启动时恢复它。

为了解决这个问题，我们应该稍微修改这个类。我们会让你做出你认为必要的更改来解决这个问题。如果你遇到困难，你可以根据`track.model.ts`文件重命名`track.model.fixed.ts`；它包含了正确的代码。

一旦你修复了它，运行相同的`tsc`，然后运行`karma start karma.ang.conf.js`命令；你应该看到一切都是成功的。

# 测试通过

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00056.jpeg)

正如这个例子所指出的，你的代码可能在某些情况下可以正确运行，但在其他情况下可能会失败。单元测试可以找出你可能没有立即看到的逻辑错误。这在添加新功能和/或修复错误时尤为重要。强烈建议你为两者创建新的测试，然后你将至少知道你的新代码或修改后的代码在进行任何代码更改后是否正常运行。

让我们稍微转换一下思路，看看 NativeScript 测试框架；Angular 框架非常酷，但它有一个严重的限制，就是没有 NativeScript 框架调用可用，因此它限制了很多其有用性。

# NativeScript 测试框架

好的，准备好使用 NativeScript 测试框架了。安装起来非常简单，只需输入以下命令：

```ts
tns test init
```

没有理由切换测试框架，所以在提示你选择与 NativeScript 测试框架一起使用哪个测试框架时选择`jasmine`。这将安装 NativeScript 测试系统所需的所有资源。NativeScript 的测试系统也使用 Karma，并支持几种不同的测试框架，但为了一致性，我们将继续使用 Jasmine。

还记得我之前说过 Karma 使用浏览器来进行所有测试吗？我还说过 NativeScript 代码不在浏览器中运行吗？那么，为什么 NativeScript 使用 Karma？Karma 如何运行 NativeScript 代码？这是一个很好的问题！Karma 实际上被欺骗成认为你的 NativeScript 应用程序是一个浏览器。Karma 将测试上传到浏览器（即 NativeScript 应用程序），然后运行它们。因此，实际上，你的应用程序对 Karma 来说就是一个浏览器；这是 NativeScript 团队提出的一个非常巧妙的解决方案。

现在，NativeScript 测试系统的最大优点是它实际上可以测试你的所有 NativeScript 代码。它将自动在模拟器（或真实设备）中运行你的应用程序的特殊构建，以便可以运行所有的 NativeScript 代码并正确访问设备。NativeScript 测试系统的最大缺点是它需要更多的资源，因为它必须使用模拟器（或真实设备）来运行测试。因此，运行测试可能比我们在本章前面讨论的标准单元测试要耗费更多时间。

好的，现在你已经安装好了。让我们继续。所有的 NativeScript 测试文件都将在`app/tests`文件夹中。这个文件夹是在你运行`tns test init`时创建的。如果你打开这个文件夹，你会看到`example.js`。随意删除或保留这个文件。这只是一个虚拟测试，用来展示如何使用 Jasmine 格式化你的测试。

因此，对于我们的 NativeScript 测试，我选择了一个使用 NativeScript 代码的简单服务。让我们在`app/test`文件夹中创建我们的`database.service.test.ts`文件。这个文件夹中的文件可以命名为任何东西，但为了方便查找，我们将以`.test.ts`结尾。你也可以创建子目录来组织所有的测试。在这种情况下，我们将测试`app/modules/core/services/database.service.ts`文件。

如果你看一下代码，这个特定的服务实际上使用了 NativeScript 的`AppSettings`模块来从 Android 和 iOS 的系统范围存储系统中存储和检索数据。所以，这是一个很好的测试文件。让我们创建我们的测试文件：

```ts
// Import the reflect-metadata because angular needs it, even if we don't.
// We could import the entire angular library; but for unit-testing; 
// smaller is better and faster.
import 'reflect-metadata';

// Import our DatabaseService, we need at least something to test... ;-)
import { DatabaseService } from "../modules/core/services/database.service";

// We do the exact same thing as we discussed earlier; 
// we describe what test group we are testing.
describe("database.service.test", function() {

  // So that we can easily change the Testing key in case we find out later in our app
  // we need "TestingKey" for some obscure reason.
  const TestingKey = "TestingKey";

  // As before, we define a "it" function to define a test group
  it("Test Database service class", function() {

    // We are just going to create the DatabaseService class here, 
    // no need for a beforeEach.
    const dbService = new DatabaseService();

    // Lets attempt to write some data.
    dbService.setItem(TestingKey, {key: "alpha", beta: "cygnus", delta: true});

    // Lets get that data back out...
    let valueOut = dbService.getItem(TestingKey);

    // Does it match?
    expect(valueOut).toBeDefined();
    expect(valueOut.key).toBe("alpha");
    expect(valueOut.beta).toBe("cygnus");
    expect(valueOut.delta).toBe(true);

    // Lets write some new data over the same key
    dbService.setItem(TestingKey, {key: "beta", beta: true});

    // Lets get the new data
    valueOut = dbService.getItem(TestingKey);

    // Does it match?
    expect(valueOut).toBeDefined();
    expect(valueOut.key).toBe("beta");
    expect(valueOut.beta).toBe(true);
    expect(Object.keys(valueOut).length).toBe(2);

    // Lets remove the key
    dbService.removeItem(TestingKey);

    // Lets make sure the key is gone
    valueOut = dbService.getItem(TestingKey);
    expect(valueOut).toBeFalsy();
  });
});
```

你可能已经能够很容易地阅读这个测试文件。基本上，它调用数据库服务几次，用不同的值设置相同的键。然后，它要求数据库服务返回存储的值，并验证结果是否与我们存储的相匹配。然后，我们告诉数据库服务删除我们的存储键，并验证该键是否消失，一切都很简单。这个文件中唯一不同的是`include 'reflect-metadata'`。这是因为数据库服务在其中使用了元数据，所以我们必须确保在加载数据库服务类之前加载元数据类。

# 运行测试

让我们尝试测试这个应用程序；要运行你的测试，输入以下命令：

```ts
tns test android
```

或者，你可以运行以下命令：

```ts
tns test ios
```

这将启动测试，你应该会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00057.jpeg)

请注意，屏幕上有一个`ERROR`；这是一个虚假的错误。基本上，当应用程序完成运行其测试时，它会退出。Karma 看到应用程序意外退出并将其记录为`ERROR` Disconnected。导入信息是错误下面的一行，那里写着`Executed 2 of 2 SUCCESS`。这意味着它运行了两个不同的`described`测试（即我们的 test.ts 文件和额外的 example.js 文件）。

您可能还注意到我们的测试文件与 Angular 测试文件相同。这是因为它们都使用 Jasmine 和 Karma。因此，测试文件可以设置得几乎相同。在这种特定情况下，因为测试实际上是在您的应用程序内部运行的，任何插件、代码和模块，包括任何本地代码，都可以进行测试。这就是使 NativeScript 测试框架更加强大和有用的原因。然而，它的最大优势也是它的弱点。由于它必须在运行的 NativeScript 应用程序内部运行，因此需要更多的时间来构建、启动和运行所有测试。这就是标准的 Angular 测试框架在 NativeScript 测试框架上的优势所在。任何不使用任何 NativeScript 特定代码的内容几乎可以立即从命令行运行，开销很小。您的测试运行得越快，您就越有可能频繁地运行它们。

# 总结

在本章中，我们讨论了如何进行单元测试以及进行单元测试的两种方法的利弊。简而言之，Angular 测试适用于不调用任何 NativeScript 特定代码的通用 TypeScript 代码，并且可以快速运行您的测试。NativeScript 测试框架在 NativeScript 应用程序内部运行，并且可以完全访问您编写的任何内容以及普通 NativeScript 应用程序可以执行的任何操作。然而，它需要 NativeScript 应用程序在运行测试之前运行，因此可能需要完整的构建步骤。

现在我们已经讨论了两种类型的单元测试，请继续保持您的测试帽。在下一章中，我们将介绍如何进行端到端测试或全屏和应用程序测试，以测试您的出色应用程序。


# 第十三章：使用 Appium 进行集成测试

在前一章中，我们探讨了如何进行单元测试，但单元测试并不能让你测试按钮在你的应用中是否仍然实际运行函数，或者用户向左滑动时会发生什么。为此，我们需要应用程序测试或端到端测试。好吧，让我们开始学习端到端测试；这是测试变得复杂和有趣的地方。

在本章中，我们将涵盖以下主题：

+   Appium 测试框架

+   编写 MochaJS、ChaiJS 和 ShouldJS 测试

+   如何查找并与屏幕上的元素交互

+   如何运行测试

+   Travis 和 GitHub 集成

# 集成测试

有几个完整的应用程序框架，但我们将向您展示如何使用 Appium（[`appium.io`](http://appium.io)）。Appium 是一个很棒的开源应用程序测试框架。Appium 支持 iOS 和 Android，这使它非常适合进行所有的设备测试。您想要开始创建测试，以测试应用程序中的基本流程，甚至创建更复杂的测试，以测试应用程序中的替代流程。

让我们先安装它；运行以下命令：

```ts
npm install appium wd nativescript-dev-appium --save-dev
```

上述命令安装了 Appium、Appium 通信驱动**WD**（[`admc.io/wd/`](http://admc.io/wd/)）和**NativeScript 驱动**（[`github.com/NativeScript/nativescript-dev-appium`](https://github.com/NativeScript/nativescript-dev-appium)）。WD 驱动是与 Appium 和 NativeScript 驱动进行通信的东西。`nativescript-dev-appium`是与 WD 和您的测试代码进行交互的驱动程序。实际上，NativeScript 驱动只是 WD 驱动的一个非常薄的包装器，它只是简化了一些配置，然后将 WD 驱动暴露给您的应用程序。因此，交互命令将在 WD 文档中找到。

应用程序/集成测试需要更多的工作，因为你必须以编程方式运行它，就像普通用户与你的应用程序交互一样。因此，你必须做一些事情，比如找到按钮元素，然后执行`button.tap()`。因此，你的测试可能会有点冗长，但这样可以测试任何和所有功能。不利的一面是这需要更多的时间来运行，并且在更改屏幕时需要更多的维护工作。然而，好处是当你添加代码时，它会自动验证你的应用程序在每个屏幕上是否仍然正常运行，并且你可以在多台设备和分辨率上进行测试，同样也是自动的。

安装后，你的根文件夹中将会有一个全新的`e2e-tests`文件夹。这个文件夹是你所有端到端测试文件的存放地。现在，你需要知道的一件事是，Appium NativeScript 驱动程序使用 MochaJS 测试框架（[`mochajs.org/`](https://mochajs.org/)）。Mocha 测试框架类似于我们在前一章讨论过的 Jasmine 框架。它使用相同的`describe`和`it`函数来开始测试，就像 Jasmine 一样。此外，它还使用了与 Mocha 测试框架和 WD 驱动程序紧密配合的 Chai（[`chaijs.com/`](http://chaijs.com/)）和 ShouldJS（[`github.com/shouldjs/should.js`](https://github.com/shouldjs/should.js)）测试框架。

另一件事需要注意的是，所有这些都是围绕纯 JavaScript 设计的。你可以为 Mocha、Should 和 Chai 获取类型，但对于 NativeScript Appium 驱动程序或 WD 驱动程序，类型不存在。你可以使用 TypeScript，但这有点尴尬，因为命令不仅仅是基于 WD 的命令，而是通过 mocha 链接在一起。TypeScript 很容易混淆你所在的上下文。因此，大多数 Appium 测试是用纯 JavaScript 而不是 TypeScript 创建的。但是，如果你愿意，可以自由使用 TypeScript；只需确保在运行测试之前运行`tsc`来构建`JS`文件。

# 配置

你需要做的另一个设置步骤是在项目的根文件夹中创建一个`appium.capabilities.json`文件。这基本上是一个配置文件，你可以用它来配置你需要在任何测试上运行的模拟器。该文件在 Appium 网站上有文档，但为了让你快速上手，你可以使用我们使用的简化文件，如下所示：

```ts
{
 "android44": {
   "browserName": "",
   "appium-version": "1.6.5",
   "platformName": "Android",
   "platformVersion": "4.4",
   "deviceName": "Android 44 Emulator",
   "noReset": false,
   "app": ""
 },

 "ios10phone": {
   "browserName": "",
   "appium-version": "1.6.5",
   "platformName": "iOS",
   "platformVersion": "10.0",
   "deviceName": "iPhone 6 Simulator",
   "app": ""
 }
}
```

我们已经简化了它，并删除了所有其他模拟器条目以节省空间。但是，您可以为每个模拟器条目分配一个键--您可以告诉 Appium 使用该键来运行模拟器配置。此示例文件显示了两个配置。第一个是 Android 4.4 设备，第二个是 iOS 模拟器（iPhone 6 运行 iOS 10）。您可以在此文件中拥有任意数量的配置。运行 Appium 时，您可以使用`--runType=KEY`参数告诉它要定位哪个设备。

# 创建测试

让我们开始我们的旅程，创建一个新的测试文件：`list.test.js`。此文件将测试我们的混合列表屏幕。屏幕的 HTML（`/app/modules/mixer/components/mix-list.component.html`）如下所示：

```ts
<ActionBar title="Compositions" class="action-bar">
   <ActionItem (tap)="add()" ios.position="right">
     <Button [text]="'fa-plus' | fonticon" class="fa action-item"></Button>
   </ActionItem>
</ActionBar>
<ListView [items]="(mixer$ | async)?.compositions | orderBy: 'order'" class="list-group">
 <ng-template let-composition="item">
   <GridLayout rows="auto" columns="100,*,auto" class="list-group-item">
     <Button [text]="'fa-pencil' | fonticon" (tap)="edit(composition)" row="0" col="0" class="fa"></Button>
     <Label [text]="composition.name" (tap)="select(composition)" row="0" col="1" class="h2"></Label>
     <Label [text]="composition.tracks.length" row="0" col="2" class="text-right"></Label>
   </GridLayout>
 </ng-template>
</ListView> 
```

我们在这里包含了代码，以便您可以轻松地看到我们如何使用屏幕上提供的细节进行测试。

```ts
// In JavaScript code, "use strict"; is highly recommended, 
// it enables JavaScript engine optimizations.
"use strict";

// Load the Appium driver, this driver sets up our connection to Appium 
// and the emulator or device.
const nsAppium = require("nativescript-dev-appium");
```

我们需要在 JavaScript 测试代码中包含 NativeScript Appium 驱动程序；这是用于实际通信和设置 Mocha、ShouldJS、WD、Appium 和 Chia 以正常工作的内容。仅需要以下一行代码来使用：

```ts
// Just like Jasmine, Mocha uses describe to start a testing group.
describe("Simple example", function () {

 // This is fairly important, you need to give the driver time to wait
 // so that your app has time to start up on the emulator/device.
 // This number might still be too small if you have a slow machine.
 this.timeout(100000);
```

正如源代码中的注释所提到的，非常重要的是给 Appium 和模拟器启动足够的时间。因此，我们的个人默认值是`100,000`；您可以尝试不同的数字，但这是它在宣布测试失败之前等待的最长时间。具有较大值意味着您为模拟器和 Appium 提供更多时间来实际运行。Appium 会快速提供启动输出，但当它实际上初始化测试和驱动程序时，该过程需要很长时间。一旦测试开始运行，它将非常快速：

```ts
 // This holds the driver; that will be used to communicate with Appium & Device.
 let driver;

 // This is ran once before any tests are ran. (There is also a beforeEach)
 before(function () {
    // VERY, VERY important line here; you NEED a driver to communicate to your device.
    // No driver, no tests will work.
    driver = nsAppium.createDriver();
 });
```

在运行测试之前，初始化和创建驱动程序非常重要。这个驱动程序在整个测试过程中是全局的。因此，我们将在`describe`函数中全局声明它，然后使用 Mocha 的`before`函数在运行任何测试之前初始化它。

```ts
// This is ran once at the end of all the tests. (There is also a afterEach)
after(function () {

  // Also important, the Appium system works off of promises
  // so you return the promise from the after function
  // NOTICE no ";", we are chaining to the next command.
  return driver    

    // This tells the driver to quit....
    .quit()
    // And finally after it has quit we print it finished....
    .finally(function () {
       console.log("Driver quit successfully");
    });
 });
```

我们还添加了一个 Mocha after 函数，在完成所有操作时关闭驱动程序。确保在使用驱动程序时，始终正确返回它非常重要。实际上，几乎每个测试片段都是一个 promise。如果忘记返回 promise，测试工具将会混乱，并可能按顺序运行测试，甚至在测试完成之前关闭驱动程序。因此，始终返回 promise：

```ts
// Just like jasmine, we define a test here.
it("should find the + button", function () {

  // Again, VERY important, you need to return the promise
  return driver

  // This searches for an element by the Dom path; so you can find sub items.
 .elementByXPath("//" + nsAppium.getXPathElement('Button'))
```

`it` 函数的使用方式与我们在 Jasmine 中所做的一样 - 你正在描述一个你计划运行的测试，以便在测试失败时找到它。同样，我们返回 promise 链；非常重要的是，你不要忘记这样做。driver 变量是在处理模拟器时给我们不同功能的东西。因此，功能的文档在 WD 存储库中，但我会给你一个快速概述让你开始。

`.elementByXPath` 和 `.elementById` 真的是唯一两个能够很好地正确找到 NativeScript 元素的函数。然而，还有一个 `.waitForElementByXPath` 和 `.waitForElementById`，它们都等待元素显示出来。如果你查看文档，你会发现很多 `elementByXXX` 命令，但 Appium 是为浏览器设计的，而 NativeScript 不是浏览器。这就是为什么，只有一些在 nativescript-dev-appium 驱动中被模拟的命令才能在 NativeScript DOM 中找到元素。

因此，我们的测试说通过 XPath 找到一个元素。XPath 允许你深入到你的 DOM 中并找到任何级别的组件，也可以找到其他组件的子组件。因此，如果你做类似 `/GridLayout/StackLayout/Label` 的事情，它会找到一个 `Label`，它是 `StackLayout` 的子级，而 `StackLayout` 是 `GridLayout` 的子级。使用 `*//*` 将意味着你可以在 DOM 中的任何级别找到该元素。最后，`nsAppium.getXPathElement` 是一个方法，由 Nathanael Anderson 添加到官方 NativeScript 驱动中，允许我们进行跨平台的 XPath 测试。实际上，你传递给 XPath 函数的是对象的真实本地名称。例如，Android 上的按钮是 `android.widget.Button`，或者在 iOS 上可能是 `UIAButton` 或 `XCUIElementTypeButton`。因此，因为你不想硬编码 `getByElementXPath("android.widget.Button")`，这个辅助函数将 NativeScript 的 `Button` 转换为 NativeScript 在创建按钮时实际使用的底层操作系统元素。如果将来添加一个使用 `getXPathElement` 不知道的元素的插件，你仍然可以使用这些测试的真实元素名称。

```ts
     // This element should eventually exist
     .text().should.eventually.exist.equal('\uf067');
 });
```

`.text()`是 Appium 驱动程序公开的函数，用于获取它找到的元素的文本值。`.should.eventually.exist.equal`是 Mocha 和 Should 代码。我们基本上是确保一旦找到这个项目，它实际上与 F067 的 Unicode 值匹配，在 Font-Awesome 中是加号字符（fa-plus）。一旦存在，我们就很高兴——测试要么成功，要么失败，这取决于我们是打破屏幕还是屏幕继续保持我们期望的方式。此外，在`.equal`之后，我们可以链接更多命令，比如`.tap()`，以触发按钮，如果我们想要的话。

好的，让我们看一下接下来运行的下一个测试：

```ts
it("should have a Demo label", function () {

  // Again, VERY important, you need to return the promise
  return driver

    // Find all Label elements, that has text of "Demo"
   .elementByXPath("//" + nsAppium.getXPathElement("Label") + "[@text='Demo']")

   // This item should eventually exist
   .should.eventually.exist

   // Tap it
   .tap();
});
```

这个测试搜索屏幕以显示`Demo`的`ListView`项。我们正在寻找一个包含 Demo 文本值的 NativeScript 标签（即`nsAppium.getXPathElement`）在 NativeScript DOM 中的任何位置（即`*//*`）（即`[@text='Demo']`）。这个元素应该最终存在，一旦存在，就调用`tap()`函数。现在，如果你看源代码，你会看到以下内容：

```ts
<Label [text]="composition.name" (tap)="select(composition)" row="0" col="1" class="h2"></Label>
```

所以，当`tap`被触发时，它将运行`select`函数。`select`函数最终加载`/app/modules/player/components/track-list/track-list.component.html`文件，用于在屏幕上显示该混音器项目的组成。

所有的测试都是按顺序执行的，并且应用程序的状态从一个测试保持到另一个测试。这意味着测试不像我们写单元测试时那样是独立的。

接下来我们将验证的测试是在我们点击后`Demo`标签实际上切换屏幕的下一个测试：

```ts
it("Should change to another screen", function () {

   // As usual return the promise chain...
   return driver

   // Find all Label elements, that has text of "Demo"
   .waitForElementByXPath("//" + nsAppium.getXPathElement("Label") + "[@text='Drums']")

   // This item should eventually exist
   .should.eventually.exist.text();
 });
```

所以，现在我们在一个新的屏幕上，我们将验证`ListView`是否包含一个名为`Drums`的标签。这个测试只是验证当我们在上一个测试中点击`Demo`标签时屏幕实际上是否发生了变化。我们本来可以验证文本值，但如果它存在，我们就没问题了。所以，让我们看看下一个测试：

```ts
it("Should change mute button", function () {

  // Again, returning the promise
  return driver

  // Find all Label elements that contains the FA-Volume
  .waitForElementByXPath("//" + nsAppium.getXPathElement("Label") + "[@text='\uf028']")

  // This item should eventually exist
  .should.eventually.exist

  // It exists, so tap it...
  .tap()

  // Make sure the text then becomes the muted volume symbol
  .text().should.eventually.become("\uf026");
});

// This closes the describe we opened at the top of this test set.
});
```

我们的最后一个示例测试展示了链接。我们搜索具有音量控制符号的标签。然后，一旦它存在，我们点击它。然后，我们验证文本实际上变成了关闭音量符号。`f028`是`fa-volume-up`的 Font Awesome Unicode 值，`f026`是`fa-volume-off`的 Font Awesome Unicode 值。

所以现在你有了这个非常酷的测试，你想要启动你的模拟器。模拟器应该已经在运行。你还应该确保你的设备上有最新版本的应用程序。然后，要运行测试，只需输入以下命令：

```ts
npm run appium --runType=android44
```

确保你输入你将要使用的运行类型配置，并且几分钟后你应该会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00058.jpeg)

请记住，Appium 的端到端测试需要一段时间才能启动，所以如果它看起来冻结了一段时间，不要惊慌并退出。第一个测试可能需要 24 秒，每个额外的测试需要几秒。第一个测试包含了所有的时间。Appium 在启动驱动程序和模拟器上的应用程序时需要很长时间是正常的。这种延迟通常发生在你看到前几行文本打印出来之后，就像前面的屏幕显示的那样，所以，请耐心等待。

# 更多的 Appium 测试

我想要包括另一个测试（在这个应用程序中没有使用）我以前为一个不同的项目编写过，因为这将让你了解 Appium 有多么强大：

```ts
it("should type in an element", function (done) {
  driver
  .elementByXPath('//' + nsAppium.getXPathElement("EditText") + "[@text='Enter your name']") 
  .sendKeys('Testing')
  .text()
  .then(function (v) {
     if ('Testing' !== v) {
        done(new Error("Value in name field does not match"));
     } else {
        done();
     }
   }, done);
 });
});
```

你可能注意到的第一件事是，我没有返回 promise 链。这是因为这个例子展示了如何使用`it`的异步支持。对于异步支持，你可以使用 promise 或者让传入`it`的函数有一个`done`回调函数。当 Mocha 检测到`it`中的回调函数时，它将以异步模式运行你的`it`测试，并且不需要 promise 来让它知道可以继续进行下一个测试。有时，你可能只想保持完全控制，或者你可能正在调用需要异步回调的代码。

这个测试查找包含`输入你的名字`的`EditText`元素。然后，它使用`sendKeys`实际输入*Testing*。接下来，它要求从字段中获取`text`，并使用 promise 的`then`部分来检查该值是否与硬编码的 testing 相匹配。当所有的操作都完成时，它调用`done`函数。如果你向`done`函数传递一个`Error`对象，那么它就知道测试失败了。所以，你可以在`if`语句中看到我们传递了一个`new Error`，并且我们将`done`函数放在`then`语句的`catch`部分。

我们只是触及了 Appium、Should、Mocha 和 Chia 可以做的一小部分。您几乎可以控制应用程序的所有方面，就好像您手动执行每个步骤一样。最初，在您的开发中，手动测试速度要快得多。然而，当您开始构建端到端的测试时，每次进行更改时，您都可以检查应用程序是否仍然正常工作，而无需花费大量时间坐在多个设备前--您只需开始测试，稍后查看结果。

# 自动化测试

您应该注意的另一件事是，您使测试自动化程度越高，您就越有可能使用它并从中获益。如果您不断地手动运行测试，您很可能会感到恼火并停止运行它们。因此，在我们看来，自动化这一点至关重要。由于有许多关于这个主题的书籍，我们只会给您一些指针，让您可以进行研究，然后继续前进。

大多数源代码控制系统都允许您创建钩子。通过这些钩子，您可以创建一个提交钩子，以便在检入任何新代码时运行您的测试框架。这些钩子通常很容易创建，因为它们只是简单的脚本，每次提交时都会运行。

此外，如果您正在使用 GitHub，有一些网站（如 Travis）可以轻松地与之集成，而无需进行任何钩子更改。

# GitHub 和 Travis 集成

以下是如何与 GitHub 和 Travis 进行一些集成；这将允许我们在前一章中讨论的 NativeScript 测试框架自动在每次更改或拉取请求时运行您的测试。在 GitHub 存储库的根目录中创建一个新的`.travis.yml`文件。此文件应如下所示：

```ts
language: android

jdk: oraclejdk8

android:
 components:
 - tools
 - platform-tools
 - build-tools-25.0.2
 - android-25
 - extra-android-m2repository
 - sys-img-armeabi-v7a-android-21

before_cache:
 - rm -f $HOME/.gradle/caches/modules-2/modules-2.lock

cache:
 directories:
 - .nvm
 - $HOME/.gradle/caches/
 - $HOME/.gradle/wrapper/

install:
 - nvm install node
 - npm install -g nativescript
 - tns usage-reporting disable
 - tns error-reporting disable

before_script:
 - echo no | android create avd --force -n test -t android-21 -b armeabi-v7a
 - emulator -avd test -no-audio -no-window &
 - android-wait-for-emulator

script:
 - npm run travissetup
 - npm run travistest
```

基本上，这配置了 Travis 启动 Android 模拟器；它等待模拟器启动，然后运行`npm`命令。您可以从您的`package.json`中了解这些`npm`命令的作用。

因此，在您的根应用程序中，也就是您的应用程序的 package.json 文件中，您需要添加以下键：

```ts
"scripts": {
   "travissetup": "npm i && tns platform add android && tns build android",
   "travistest": "tns test android"
}
```

通过这两个更改，Travis 将自动测试您存储库中的每个拉取请求，这意味着您可以编写代码，Travis 将持续进行所有单元测试。

此外，您可以更改前面的 Travis 配置文件，以添加 Appium 的安装和运行，只需执行以下操作：

+   将 Appium 依赖项添加到您的主`package.json`依赖项中。

+   在项目的根目录中添加一个具有`travisAndroid`键的`appium.capabilities.json`。

+   在`package.json`文件中的`travistest`键中添加`&& npm run appium --runType=travisAndroid`。

GitHub 已经内置了与 Travis 的集成，因此很容易进行文档化并运行。如果您使用 Gitlabs，可以使用 Gitlabs CI 系统进行测试。此外，您还可以使用存储库钩子来使用许多其他可用的持续集成服务。最后，您还可以开发自己的持续集成服务。

# 摘要

在本章中，我们介绍了如何安装和运行 Appium，如何构建完整的端到端测试以及如何使用测试框架全面测试您的屏幕。此外，我们还介绍了自动运行单元测试和 Appium 的重要性，而您可以使用 Travis 和 GitHub 来实现这一点。

现在紧紧抓住——我们将快速转向并开始讨论如何部署和使用 Webpack 来优化您的发布构建。


# 第十四章：使用 webpack 进行部署准备

我们希望将我们的应用程序部署到两个主要的移动应用商店，苹果应用商店和谷歌 Play 商店；然而，有一些事情我们需要做来准备我们的应用程序进行分发。

为了确保你使用最小的 JavaScript 大小，以及 Angular 的 AoT 编译器来帮助我们的应用尽可能快地执行，我们将使用 webpack 来捆绑所有内容。值得注意的是，webpack 并不是创建可分发的 NativeScript 应用程序的必需条件。然而，它提供了非常好的好处，应该使它成为任何人在分发他们的应用程序时的重要步骤。

在本章中，我们将涵盖以下主题：

+   为 NativeScript for Angular 项目安装 webpack

+   准备项目以使用 webpack 进行捆绑

+   解决各种 webpack 捆绑问题

+   编写自己的自定义 webpack 插件以解决特定情况的入门指南

# 使用 webpack 来捆绑应用程序

如果不是 Sean Larkin，你可能永远不会听说过 webpack。他在捆绑器社区的贡献和参与帮助将 webpack 引入了 Angular CLI，并使其成为许多事情的主要*首选*捆绑器。我们非常感谢他在社区中的努力和善意。

# 准备使用 webpack

让我们看看如何利用 webpack 来减少我们的 NativeScript for Angular 应用程序的打包大小，以确保它在用户的移动设备上执行得尽可能优化。

让我们首先安装插件：

```ts
npm install nativescript-dev-webpack --save-dev
```

这将自动创建一个`webpack.config.js`文件（在项目的根目录），预先配置了一个基本设置，可以让你在大多数应用中进一步使用。此外，它还创建了一个`tsconfig.aot.json`文件（同样在项目的根目录），因为 NativeScript 的 webpack 使用将使用 Angular 的 AoT 编译器进行捆绑。它还在我们的`package.json`中添加了一些巧妙的 npm 脚本，以帮助处理我们想要的各种捆绑选项；请考虑以下示例：

+   `npm run build-android-bundle` 用于构建 Android

+   `npm run build-ios-bundle` 用于构建 iOS

+   `npm run start-android-bundle` 用于在 Android 上运行

+   `npm run start-ios-bundle` 用于在 iOS 上运行

但是，在我们尝试这些新命令之前，我们需要审查我们的应用程序的一些内容。

我们应该首先确保所有 NativeScript 导入路径都以`tns-core-modules/[module]`开头；请考虑以下示例：

```ts
BEFORE:
import { isIOS } from 'platform';
import { topmost } from 'ui/frame';
import * as app from 'application';

AFTER:
import { isIOS } from 'tns-core-modules/platform';
import { topmost } from 'tns-core-modules/ui/frame';
import * as app from 'tns-core-modules/application';
```

我们现在将浏览我们的应用程序并执行此操作。这对开发和生产构建都有效。

你可能会想，*嘿！如果我们需要在事后遍历整个代码库并更改导入，为什么你还要使用另一种形式？*

非常关注！实际上有很多示例显示了方便的简写导入路径，所以我们选择在本章中始终使用它来构建应用程序，以证明它对开发非常有效，以帮助避免混淆，以防将来遇到这样的示例。此外，事后编辑以准备 webpack 并不需要太多时间，现在你知道了。

立即运行以下命令：

```ts
npm run build-ios-bundle
```

我们可以看到以下错误——我已经列举出来——我们将在下一节中按顺序提出解决方案：

1.  意外值`SlimSliderDirective`在`/path/to/TNSStudio/app/modules/player/directives/slider.directive.d.ts`中的模块 PlayerModule 中声明。请添加`@Pipe/@Directive/@Component`注释。

1.  无法确定`SlimSliderDirective`类在`/path/to/TNSStudio/app/modules/player/directives/slider.directive.android.ts`中的模块！将`SlimSliderDirective`添加到`NgModule`中以修复它。无法确定`SlimSliderDirective`类在`/path/to/TNSStudio/app/modules/player/directives/slider.directive.ios.ts`中的模块！将`SlimSliderDirective`添加到`NgModule`中以修复它。

1.  错误在静态解析符号值时遇到错误。调用函数`ModalDialogParams`，不支持函数调用。考虑用对导出函数的引用替换函数或 lambda，解析符号`RecorderModule`在`/path/to/TNSStudio/app/modules/recorder/recorder.module.ts`中，解析符号`RecorderModule`在`/path/to/TNSStudio/app/modules/recorder/recorder.module.ts`中。

1.  入口模块未找到：错误：无法解析`/path/to/TNSStudio/app`中的`./app.css`。

1.  错误在[copy-webpack-plugin]无法在`/path/to/TNSStudio/app/app.css`中找到`app.css`。

前三个错误纯粹与 Angular **Ahead of Time** (**AoT**)编译相关。最后两个纯粹与 webpack 配置相关。让我们看看每个错误以及如何正确解决它。

# 解决方案＃1：意外值'SlimSliderDirective...'

考虑前一节中提到的第一个完整错误：

```ts
ERROR in Unexpected value 'SlimSliderDirective in /path/to/TNSStudio/app/modules/player/directives/slider.directive.d.ts' declared by the module 'PlayerModule in /path/to/TNSStudio/app/modules/player/player.module.ts'. Please add a @Pipe/@Directive/@Component annotation.
```

解决前面的错误是安装额外的 webpack 插件：

```ts
npm install nativescript-webpack-import-replace --save-dev
```

然后，打开`webpack.config.js`并配置插件如下：

```ts
function getPlugins(platform, env) {
    let plugins = [
      ...
      new ImportReplacePlugin({
          platform: platform,
          files: [
              'slider.directive'
          ]
      }),
      ...
```

这将在`app/modules/players/directives/index.ts`中找到`slider.directive`的导入，并附加正确的目标平台后缀，这样 AoT 编译器就会选择正确的目标平台实现文件。

在撰写本书时，对于该错误尚不存在解决方案，因此我们开发了`nativescript-webpack-import-replace`插件来解决。由于您可能会遇到需要通过插件提供一些额外 webpack 帮助的 webpack 捆绑情况，我们将分享我们如何开发插件来解决该错误的概述，以防您遇到其他可能需要您创建插件的模糊错误。

首先让我们看看如何解决最初剩下的错误，然后我们将重点介绍 webpack 插件开发。

# 解决方案＃2：无法确定 SlimSliderDirective 类的模块...

考虑*准备使用 webpack*部分提到的第二个完整错误：

```ts
ERROR in Cannot determine the module for class SlimSliderDirective in /path/to/TNSStudio/app/modules/player/directives/slider.directive.android.ts! Add SlimSliderDirective to the NgModule to fix it.
Cannot determine the module for class SlimSliderDirective in /path/to/TNSStudio/app/modules/player/directives/slider.directive.ios.ts! Add SlimSliderDirective to the NgModule to fix it.
```

解决上述错误的方法是打开`tsconfig.aot.json`，并进行以下更改：

```ts
BEFORE:
  ...
  "exclude": [
    "node_modules",
    "platforms"
  ],

AFTER:
  ...
  "files": [
 "./app/main.ts"
 ]
```

由于 AoT 编译使用`tsconfig.aot.json`配置，我们希望更具体地指定要编译的文件。由于`./app/main.ts`是引导应用程序的入口点，我们将针对该文件并删除`exclude`块。

如果我们现在尝试进行捆绑，我们将解决我们看到的错误；然而，我们将看到以下*新*错误：

```ts
ERROR in .. lazy
Module not found: Error: Can't resolve '/path/to/TNSStudio/app/modules/mixer/mixer.module.ngfactory.ts' in '/path/to/TNSStudio'
 @ .. lazy
 @ ../~/@angular/core/@angular/core.es5.js
 @ ./vendor.ts

ERROR in .. lazy
Module not found: Error: Can't resolve '/path/to/TNSStudio/app/modules/recorder/recorder.module.ngfactory.ts' in '/path/to/TNSStudio'
 @ .. lazy
 @ ../~/@angular/core/@angular/core.es5.js
 @ ./vendor.ts
```

这是因为我们的目标是`./app/main.ts`，它会分支到我们应用程序文件的所有其他导入，除了那些懒加载的模块。

解决上述错误的方法是在`files`部分中添加懒加载模块路径：

```ts
"files": [
  "./app/main.ts",
  "./app/modules/mixer/mixer.module.ts",
 "./app/modules/recorder/recorder.module.ts"
 ],
```

好了，我们解决了`lazy`错误；然而，现在这揭示了几个*新*错误，如下所示：

```ts
ERROR in /path/to/TNSStudio/app/modules/recorder/components/record.component.ts (128,19): Cannot find name 'CFRunLoopGetMain'.
ERROR in /path/to/TNSStudio/app/modules/recorder/components/record.component.ts (130,9): Cannot find name 'CFRunLoopPerformBlock'.
ERROR in /path/to/TNSStudio/app/modules/recorder/components/record.component.ts (130,40): Cannot find name 'kCFRunLoopDefaultMode'.
ERROR in /path/to/TNSStudio/app/modules/recorder/components/record.component.ts (131,9): Cannot find name 'CFRunLoopWakeUp'.
```

就在此时...

放克灵魂兄弟。

是的，你可能正在唱 Fatboy Slim 或即将失去理智，我们理解。使用 webpack 进行捆绑有时可能会是一次非常冒险的经历。我们能提供的最好建议是保持耐心和勤奋，逐个解决错误；我们几乎到了。

解决上述错误的方法是包含 iOS 和 Android 平台声明，因为我们在应用程序中使用原生 API：

```ts
"files": [
  "./app/main.ts",
  "./app/modules/mixer/mixer.module.ts",
  "./app/modules/recorder/recorder.module.ts",
  "./node_modules/tns-platform-declarations/ios.d.ts",
 "./node_modules/tns-platform-declarations/android.d.ts"
]
```

万岁，我们现在已完全解决了第二个问题。让我们继续下一个。

# 解决方案＃3：遇到静态解析符号值的错误

考虑*准备使用 webpack*部分提到的第三个完整错误：

```ts
ERROR in Error encountered resolving symbol values statically. Calling function 'ModalDialogParams', function calls are not supported. Consider replacing the function or lambda with a reference to an exported function, resolving symbol RecorderModule in /path/to/TNSStudio/app/modules/recorder/recorder.module.ts, resolving symbol RecorderModule in /path/to/TNSStudio/app/modules/recorder/recorder.module.ts
```

前面错误的解决方案是打开`app/modules/recorder/recorder.module.ts`并进行以下更改：

```ts
...
// factory functions
export function defaultModalParamsFactory() {
 return new ModalDialogParams({}, null);
};
...
@NgModule({
  ...
  providers: [
    ...PROVIDERS,
    { 
 provide: ModalDialogParams, 
 useFactory: defaultModalParamsFactory 
 }
  ],
  ...
})
export class RecorderModule { }
```

这将满足 Angular AoT 编译器静态解析符号的需求。

# 解决方案＃4 和＃5：无法解析'./app.css'

考虑在*准备使用 webpack*部分中提到的第 4 和第 5 个错误：

```ts
4\. ERROR in Entry module not found: Error: Can't resolve './app.css' in '/path/to/TNSStudio/app'

5\. ERROR in [copy-webpack-plugin] unable to locate 'app.css' at '/path/to/TNSStudio/app/app.css'
```

前面错误的解决方案实际上与我们使用特定于平台的`.ios.css`和`.android.css`有关，这是通过 SASS 编译的。我们需要更新我们的 webpack 配置，以便它知道这一点。打开`webpack.config.js`，插件已自动为我们添加，并进行以下更改：

```ts
module.exports = env => {
  const platform = getPlatform(env);

  // Default destination inside platforms/<platform>/...
  const path = resolve(nsWebpack.getAppPath(platform));

  const entry = {
    // Discover entry module from package.json
    bundle: `./${nsWebpack.getEntryModule()}`,
    // Vendor entry with third-party libraries
    vendor: `./vendor`,
    // Entry for stylesheet with global application styles
    [mainSheet]: `./app.${platform}.css`,
  };
  ...

function getPlugins(platform, env) {
  ...
  // Copy assets to out dir. Add your own globs as needed.
  new CopyWebpackPlugin([
    { from: "app." + platform + ".css", to: mainSheet },
    { from: "css/**" },
    { from: "fonts/**" },
    { from: "**/*.jpg" },
    { from: "**/*.png" },
    { from: "**/*.xml" },
  ], { ignore: ["App_Resources/**"] }),
  ...
```

好吧，我们现在已经解决了所有捆绑问题，或者等一下....**我们吗？！**

我们还没有尝试在模拟器或设备上运行应用程序。如果我们现在尝试使用`npm run start-ios-bundle`或通过 XCode 或`npm run start-android-bundle`进行此操作，当它尝试启动时，您可能会遇到应用程序崩溃的错误，如下所示：

```ts
JS ERROR Error: No NgModule metadata found for 'AppModule'.
```

前面错误的解决方案是确保您的应用程序包含一个`./app/main.aot.ts`文件，其中包含以下内容：

```ts
import { platformNativeScript } from "nativescript-angular/platform-static";
import { AppModuleNgFactory } from "./app.module.ngfactory";

platformNativeScript().bootstrapModuleFactory(AppModuleNgFactory);
```

如果您还记得，我们有一个演示组合设置，它从`audio`文件夹加载其轨道文件。我们还利用了 font-awesome 图标，借助于从`assets`文件夹加载的 font-awesome.css 文件。我们需要确保这些文件夹也被复制到我们的生产 webpack 构建中。打开`webpack.config.js`并进行以下更改：

```ts
new CopyWebpackPlugin([
  { from: "app." + platform + ".css", to: mainSheet },
  { from: "assets/**" },
 { from: "audio/**" },
  { from: "css/**" },
  { from: "fonts/**" },
  { from: "**/*.jpg" },
  { from: "**/*.png" },
  { from: "**/*.xml" },
], { ignore: ["App_Resources/**"] }),
```

成功！

现在我们可以使用以下命令运行我们捆绑的应用程序，而不会出现错误：

+   `npm run start-ios-bundle`

+   打开 XCode 项目并运行`npm run start-android-bundle`

值得注意的是，我们为发布应用启用 webpack 捆绑所做的所有更改在开发中也完全有效，因此请放心，您目前只是改进了应用的设置。

# 绕道-开发 webpack 插件概述

现在我们想要回到我们在捆绑应用程序时遇到的第一个错误，即：

+   ERROR in 意外值`SlimSliderDirective`在`/path/to/TNSStudio/app/modules/player/directives/slider.directive.d.ts`中由`PlayerModule`模块声明在`/path/to/TNSStudio/app/modules/player/player.module.ts`中。请添加`@Pipe/@Directive/@Component`注释。

在撰写本书时，尚不存在此错误的解决方案，因此我们创建了`nativescript-webpack-import-replace`（[`github.com/NathanWalker/nativescript-webpack-import-replace`](https://github.com/NathanWalker/nativescript-webpack-import-replace)）插件来解决这个问题。

详细开发 webpack 插件超出了本书的范围，但我们希望为您提供一些过程的亮点，以防您最终需要创建一个来解决应用程序的特定情况。

我们首先创建了一个单独的项目，其中包含一个`package.json`文件，以便像安装其他 npm 插件一样安装我们的 webpack 插件：

```ts
{
  "name": "nativescript-webpack-import-replace",
  "version": "1.0.0",
  "description": "Replace imports with .ios or .android suffix for target mobile platforms.",
  "files": [
    "index.js",
    "lib"
  ],
  "engines": {
    "node": ">= 4.3 < 5.0.0 || >= 5.10"
  },
  "author": {
    "name": "Nathan Walker",
    "url": "http://github.com/NathanWalker"
  },
  "keywords": [
    "webpack",
    "nativescript",
    "angular"
  ],
  "nativescript": {
    "platforms": {
      "android": "3.0.0",
      "ios": "3.0.0"
    },
    "plugin": {
      "nan": "false",
      "pan": "false",
      "core3": "true",
      "webpack": "true",
      "category": "Developer"
    }
  },
  "homepage": "https://github.com/NathanWalker/nativescript-webpack-import-replace",
  "repository": "NathanWalker/nativescript-webpack-import-replace",
  "license": "MIT"
}
```

`nativescript`关键字实际上有助于在各种 NativeScript 插件列表网站上对此插件进行分类。

然后，我们创建了`lib/ImportReplacePlugin.js`来表示我们可以导入并在 webpack 配置中使用的实际插件类。我们将此文件创建在`lib`文件夹中，以防需要添加额外的支持文件来帮助我们的插件进行良好的分离。在这个文件中，我们通过定义一个包含我们插件构造函数的闭包来设置导出：

```ts
exports.ImportReplacePlugin = (function () {
  function ImportReplacePlugin(options) {
    if (!options || !options.platform) {
      throw new Error(`Target platform must be specified!`);
    }

    this.platform = options.platform;
    this.files = options.files;
    if (!this.files) {
      throw new Error(`An array of files containing just the filenames to replace with platform specific names must be specified.`);
    }
  }

  return ImportReplacePlugin;
})();
```

这将获取我们 webpack 配置中定义的目标`platform`，并将其作为选项传递，同时还有一个`files`集合，其中包含我们需要替换的所有导入文件的文件名。

然后，我们希望在 webpack 的`make`生命周期钩子中插入，以便抓住正在处理的源文件以进行解析：

```ts
ImportReplacePlugin.prototype.apply = function (compiler) {
    compiler.plugin("make", (compilation, callback) => {
      const aotPlugin = getAotPlugin(compilation);
      aotPlugin._program.getSourceFiles()
        .forEach(sf => {
          this.usePlatformUrl(sf)
        });

      callback();
    })
 };

  function getAotPlugin(compilation) {
    let maybeAotPlugin = compilation._ngToolsWebpackPluginInstance;
    if (!maybeAotPlugin) {
      throw new Error(`This plugin must be used with the AotPlugin!`);
    }
    return maybeAotPlugin;
  }
```

这抓住了所有的 AoT 源文件。然后我们设置一个循环，逐个处理它们，并为我们需要的内容添加处理方法：

```ts
ImportReplacePlugin.prototype.usePlatformUrl = function (sourceFile) {
    this.setCurrentDirectory(sourceFile);
    forEachChild(sourceFile, node => this.replaceImport(node));
}

ImportReplacePlugin.prototype.setCurrentDirectory = function (sourceFile) {
   this.currentDirectory = resolve(sourceFile.path, "..");
}

ImportReplacePlugin.prototype.replaceImport = function (node) {
    if (node.moduleSpecifier) {
      var sourceFile = this.getSourceFileOfNode(node);
      const sourceFileText = sourceFile.text;
      const result = this.checkMatch(sourceFileText);
      if (result.index > -1) {
        var platformSuffix = "." + this.platform;
        var additionLength = platformSuffix.length;
        var escapeAndEnding = 2; // usually "\";" or "\';"
        var remainingStartIndex = result.index + (result.match.length - 1) + (platformSuffix.length - 1) - escapeAndEnding;

        sourceFile.text =
          sourceFileText.substring(0, result.index) +
          result.match +
          platformSuffix +
          sourceFileText.substring(remainingStartIndex);

        node.moduleSpecifier.end += additionLength;
      }
    }
  }

  ImportReplacePlugin.prototype.getSourceFileOfNode = function (node) {
    while (node && node.kind !== SyntaxKind.SourceFile) {
      node = node.parent;
    }
    return node;
  }

  ImportReplacePlugin.prototype.checkMatch = function (text) {
    let match = '';
    let index = -1;
    this.files.forEach(name => {
      const matchIndex = text.indexOf(name);
      if (matchIndex > -1) {
        match = name;
        index = matchIndex;
      }
    });
    return { match, index };
  }
```

构建 webpack 插件的一个有趣部分（*可能是最具挑战性的*）是处理源代码的**抽象语法树**（**ASTs**）。我们插件的一个关键方面是从 AST 中获取“源文件”节点，方法如下：

```ts
ImportReplacePlugin.prototype.getSourceFileOfNode = function (node) {
  while (node && node.kind !== SyntaxKind.SourceFile) {
    node = node.parent;
  }
  return node;
}
```

这有效地清除了除源文件之外的任何其他节点，因为这是我们的插件需要处理的所有内容。

最后，我们在根目录创建了一个`index.js`文件，只需导出插件文件供使用：

```ts
module.exports = require("./lib/ImportReplacePlugin").ImportReplacePlugin;
```

借助这个 webpack 插件，我们能够完全解决我们应用程序中遇到的所有 webpack 捆绑错误。

# 总结

在本章中，我们通过将 webpack 添加到构建链中，为应用程序的分发做好了准备，以帮助确保我们的 JavaScript 大小最小，代码执行性能最佳。这也使得 Angular 的 AoT 编译在我们的应用程序上可用，有助于提供我们代码的最佳性能。

在此过程中，我们提供了一些解决各种 webpack 捆绑错误的解决方案，这些错误可能在应用程序开发过程中遇到。此外，我们还从高层次上看了一下开发自定义 webpack 插件，以帮助解决应用程序中特定的错误条件，从而实现成功的捆绑。

现在我们已经有了应用程序代码的最佳捆绑，我们现在准备完成我们的分发步骤，最终在下一章部署我们的应用程序。


# 第十五章：部署到苹果应用商店

在这一章中，我们将重点讨论如何将我们的应用部署到苹果应用商店。我们将要遵循几个重要的步骤，所以请密切关注这里呈现的所有细节。

无论您是否需要使用签名证书来构建我们应用的发布目标，生成应用图标和启动画面，还是在 XCode 中为上传到应用商店归档我们的应用，我们将在本章中涵盖所有这些主题。

NativeScript 专家、Progress 的开发者倡导者 TJ VanToll 撰写了一篇关于部署步骤的优秀文章，标题为*8 Steps to Publish Your NativeScript App to the App Stores* ([`www.nativescript.org/blog/steps-to-publish-your-nativescript-app-to-the-app-stores`](https://www.nativescript.org/blog/steps-to-publish-your-nativescript-app-to-the-app-stores))。我们将从该文章中摘录内容，并在本章和下一章中尽可能扩展各个部分。

没有必要欺骗你——将 iOS 应用发布到 iOS 应用商店是您在软件开发生涯中将经历的最痛苦的过程之一。所以，如果您在这些步骤中遇到困难或困惑，只需知道不仅是您——每个人在首次发布 iOS 应用时都会感到沮丧。

本章涵盖以下主题：

+   如何创建应用 ID 和生产证书以签署您的应用发布目标

+   如何配置 NativeScript 应用程序所需的适当元数据以进行发布

+   如何处理应用图标和启动画面

+   使用 NativeScript CLI 将您的构建上传到 iTunes Connect

# 为应用商店分发做准备

要将 iOS 应用程序部署到 iOS 应用商店，您绝对必须拥有一个活跃的苹果开发者帐户。加入该计划每年需要 99 美元，并且您可以在[developer.apple.com/register](https://developer.apple.com/register)上注册。

# 应用 ID、证书和配置文件

一旦您创建了苹果开发者帐户，您将需要在苹果开发者门户上创建应用 ID、生产证书和分发配置文件。这是整个过程中最繁琐的部分，因为需要一些时间来学习这些各种文件的作用以及如何使用它们：

1.  对于我们的应用，我们将从以下内容开始创建应用 ID：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00059.jpeg)

1.  一旦我们创建了这个应用 ID，我们现在可以创建一个生产证书：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00060.jpeg)

1.  选择继续。然后，下一个屏幕将提供有关如何签署您的生产证书的说明，接下来我们将详细介绍。首先，打开`/Applications/Utilities/Keychain Access.app`，然后转到左上角菜单，选择 Certificate Assistant | Request a Certificate from a Certificate Authority，使用此设置：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00061.jpeg)

这将在您选择的任何位置保存一个签名请求文件，您将在下一步中需要它。

1.  现在，在门户网站的这一步中选择签名请求文件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00062.jpeg)

1.  在下一个屏幕上，非常重要的是下载然后双击需要安装到您的钥匙串的文件，因为它指定了：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00063.jpeg)

1.  双击文件安装到钥匙串时，可能会提示您提供要安装文件的钥匙串；使用*登录*钥匙串将正常工作：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00064.jpeg)

现在，在您的钥匙串访问应用程序中应该看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00065.jpeg)

1.  现在，您可以退出钥匙串访问。

1.  接下来，我们要创建一个分发配置文件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00066.jpeg)

1.  在下一个屏幕上，只需确保选择您创建的应用程序 ID：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00067.jpeg)

1.  然后，在下一个屏幕上，您应该能够选择您创建的分发证书：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00068.jpeg)

1.  然后，您将能够为配置文件命名：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00069.jpeg)

1.  您可以下载配置文件并将其放在`ios_distribution.cer`文件旁边；但是，没有必要打开该配置文件，因为 XCode 将处理其他所有内容。

# 配置应用程序元数据，如应用程序 ID 和显示名称

iOS 和 Android 应用程序有很多信息，您需要在将应用程序部署到各自的商店之前进行配置。NativeScript 为许多这些值提供了智能默认值，但在部署之前，您可能需要审查其中一些值。

# 应用程序 ID

刚刚在苹果开发者门户网站配置的应用程序 ID 是使用称为反向域名表示法的唯一标识符。我们的 NativeScript 应用程序的元数据必须匹配。我们的应用程序 ID 是`io.nstudio.nStudio`。NativeScript CLI 在创建应用程序时有一种设置应用程序 ID 的约定：

```ts
 tns create YourApp --appid com.mycompany.myappname
```

我们在创建应用程序时没有使用此选项；但是，更改我们的应用程序 ID 非常容易。

打开应用程序的根`package.json`文件，找到`nativescript`键。确保`id`属性包含您想要使用的值：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00070.jpeg)

# 显示名称

您应用程序的显示名称是用户在屏幕上看到的图标旁边的名称。默认情况下，NativeScript 根据您传递给`tns create`的值设置应用程序的显示名称，这通常不是您希望用户看到的内容。例如，运行`tns create my-app`会导致一个显示名称为`myapp`的应用程序。

要在 iOS 上更改该值，首先打开您的应用程序的`app/App_Resources/iOS/Info.plist`文件。`Info.plist`文件是 iOS 的主要配置文件，在这里，您可能希望在发布应用程序之前调整一些值。对于显示名称，您需要修改`CFBundleDisplayName`值。

这是`nStudio`的值：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00071.jpeg)尽管显示名称没有真正的字符限制，但 iOS 和 Android 都会在大约 10-12 个字符左右截断您的显示名称。

# 创建您的应用程序图标和启动画面

您的应用程序图标是用户注意到您的应用程序的第一件事。当您启动一个新的 NativeScript 应用程序时，您将获得一个占位符图标，这对于开发来说是可以的；但是，对于生产，您需要用您想要上架的图像替换占位符图标。

为了将您的生产就绪的应用程序图标文件放置到位，您需要首先创建一个代表您的应用程序的 1024 x 1024 像素的`.png`图像资产。

为了让您的生活困难，iOS 和 Android 都要求您提供各种尺寸的图标图像。不过不用担心；一旦您有了 1024 x 1024 的图像，有一些网站可以生成 Android 和 iOS 所需的各种尺寸的图像。对于 NativeScript 开发，我建议您使用 Nathanael Anderson 的 NativeScript Image Builder，该工具可在`images.nativescript.rocks`上使用。

我们将在 Photoshop 中构建我们的图标：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00072.jpeg)

然后，我们可以将其导出为`.png`并上传到`images.nativescript.rocks`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00073.jpeg)

当您点击 Go 时，将下载一个 zip 文件，其中包含您的应用程序图标和启动画面。您可以将这些图像分别复制到您的`app/App_Resources`文件夹中，用于 iOS（我们将在下一章中介绍 Android）。

现在我们已经放置了我们的应用程序图标和启动画面。

# 构建发布应用程序

由于我们在前一章已经涵盖了 webpack 捆绑问题，现在我们准备使用以下命令构建最终可发布的捆绑包：

```ts
npm run build-ios-bundle -- --release --forDevice --teamId KXPB57C8BE
```

请注意，`--teamId`对您来说将是不同的。这是在前面的命令中提供的 App ID 的前缀。

当此命令完成后，您将在`platforms/ios/build/device`文件夹中获得`.ipa`文件。请记下该文件的位置，因为您将在本指南的最后一步中需要它。

哦！希望你已经一路顺利到达这一步。现在，你已经准备好进行最后一步，即 iTunes Connect。

# 上传到 iTunes Connect

您需要做的第一件事是注册您的应用程序。要做到这一点，访问[`itunesconnect.apple.com/`](https://itunesconnect.apple.com/)，点击我的应用程序，然后点击+按钮（目前位于屏幕左上角），然后选择新应用程序。在接下来的屏幕上，确保您选择了正确的 Bundle ID，SKU 可以是您想要识别您的应用程序的任何数字；我们喜欢使用当前日期：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00074.jpeg)

提供完这些信息后，您将被带到您的应用程序仪表板，我们需要提供有关我们的应用程序的更多元数据。大部分信息都很简单，比如描述和定价，但还有一些*有趣*的部分需要处理，比如屏幕截图。

iTunes Connect 现在要求您上传两套屏幕截图，一套用于最大的 iPhone 设备（5.5 英寸显示屏），另一套用于最大的 iPad 设备（12.9 英寸设备）。苹果仍然允许您为每个 iOS 设备尺寸提供优化的屏幕截图，但如果您只提供 5.5 英寸和 12.9 英寸的屏幕截图，苹果将自动为较小的显示设备重新调整您提供的屏幕截图。

要获得这些屏幕截图，我们可以在物理 iPhone Plus 和 iPad Pro 设备上运行应用程序，但我们发现从 iOS 模拟器获取这些屏幕截图要容易得多。

在正确的模拟设备运行时，我们可以使用模拟器的*Cmd* + *S*键盘快捷键来对应用程序进行截图，这将把适当的图像保存到我们的桌面上。

到目前为止，我们已经准备就绪。我们将使用 DaVinci 等服务（[`www.davinciapps.com`](https://www.davinciapps.com/)）来优化我们的图像文件，但当我们准备好时，我们将把我们的图像拖放到 iTunes Connect 的 App 预览和屏幕截图区域。

# 上传您的.ipa 文件

我们快要完成了！一旦所有信息都被输入到 iTunes Connect 中，最后一步就是将构建的.ipa 文件与我们刚刚输入的所有信息关联起来。

我们将使用 NativeScript CLI 来完成这个过程。

请记住，你的.ipa 文件在你的应用程序的`platforms/ios/build/device`文件夹中。

运行以下命令将你的应用程序发布到 iTunes Connect：

```ts
tns publish ios --ipa <path to your ipa file>
```

就是这样。不过，有一点重要的注意事项，无论出于什么疯狂的原因，你上传 iOS 应用程序和应用程序在 iTunes Connect 中显示之间存在着相当大的延迟。我们看到这种延迟可能短至 30 秒，长至 1 小时。一旦构建出现在那里，我们就可以点击大大的“提交审核”按钮，然后祈祷。

苹果对于审核你提交的 iOS 应用程序有着臭名昭著的不定期延迟。在撰写本书时，iOS App Store 的平均审核时间大约为 2 天。

# 总结

在本章中，我们强调了发布应用程序到苹果应用商店所必须采取的关键步骤，包括签名证书、应用程序 ID、应用图标和启动画面。这个过程一开始可能看起来很复杂，但一旦你更好地理解了各个步骤，它就会变得更清晰。

我们现在在商店中有一个待审核的应用程序，并且正在朝着让我们的应用程序在全球范围内为用户提供的目标迈进。

在下一章中，让我们通过将我们的应用程序部署到 Google Play 商店来扩大我们的受众群体。


# 第十六章：部署到 Google Play

尽管与苹果应用商店相比，将应用部署到 Google Play 可能稍微简单一些，但我们仍然需要注意一些关键步骤。我们在第十四章 *使用 webpack 捆绑进行部署准备*和第十五章 *部署到苹果应用商店*中涵盖了一些准备步骤，例如使用 webpack 捆绑应用程序和准备应用程序图标和启动画面，因此我们将直接进入构建可发布的 APK。 

我们要感谢 TJ VanToll 为我们提供了一篇出色的八步文章，用于部署 NativeScript 应用（[`www.nativescript.org/blog/steps-to-publish-your-nativescript-app-to-the-app-stores`](https://www.nativescript.org/blog/steps-to-publish-your-nativescript-app-to-the-app-stores)），我们将从中插入摘录，并在可能的情况下进行扩展。

本章涵盖以下主题：

+   生成用于构建 APK 的密钥库

+   使用 NativeScript CLI 构建可发布的 APK

+   将 APK 上传到 Google Play 以供发布

# 为 Google Play 构建 APK

在您打开 Google Play 注册和发布此应用之前（这是下一步），让我们仔细检查一些事项，以确保我们的元数据是正确的。

打开`app/App_Resources/Android/app.gradle`，确保`applicationId`对于您的包名称是正确的：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00075.jpeg)

此外，还要在项目根目录下打开`package.json`，并为了谨慎起见，再次检查`nativescript.id`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00076.jpeg)

现在，您需要为您的应用生成一个可执行的 Android 文件。在 Android 上，此文件具有`.apk`扩展名，您可以使用 NativeScript CLI 生成此文件。

您在 NativeScript 开发期间使用的`tns run`命令实际上为您生成了一个`.apk`文件，并将该文件安装在 Android 模拟器或设备上。但是，对于 Google Play 发布，您创建的构建还必须进行代码签名。如果您想深入了解加密细节，可以参考 Android 的文档（[`developer.android.com/studio/publish/app-signing.html`](https://developer.android.com/studio/publish/app-signing.html)）进行代码签名，但在高层次上，您需要执行以下两个操作来创建 Android 应用的发布版本：

+   创建一个`.keystore`或`.jks`（Java 密钥库）文件

+   使用`.keystore`或`.jks`文件登录到应用程序进行构建

Android 文档为你提供了一些关于如何创建密钥库文件的选项（[`developer.android.com/studio/publish/app-signing.html#release-mode`](https://developer.android.com/studio/publish/app-signing.html#release-mode)）。我们首选的方法是`keytool`命令行实用程序，它包含在 NativeScript 为你安装的 Java JDK 中，因此应该已经在你的开发机器的命令行中可用。

要使用`keytool`为我们的应用程序生成代码签名的密钥库，我们将使用以下命令：

```ts
keytool -genkey -v -keystore nstudio.jks -keyalg RSA -keysize 2048 -validity 10000 -alias nstudio
```

`keytool`实用程序会问你一些问题，其中有一些是可选的（组织名称和城市、州和国家的名称），但最重要的是密钥库和别名的密码（稍后会详细介绍）。当我们生成密钥库时，`keytool`的过程如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00077.jpeg)

在我们继续讨论如何使用这个`.jks`文件之前，有一件重要的事情你需要知道。把这个`.jks`文件放在一个安全的地方，并且不要忘记密钥库或别名的密码。（个人而言，我喜欢使用相同的密码来简化我的生活。）Android 要求你使用完全相同的`.jks`文件来登录到应用程序的任何更新中。这意味着如果你丢失了这个`.jks`文件，或者它的密码，你将无法更新你的 Android 应用程序。你将不得不在 Google Play 中创建一个全新的条目，你现有的用户将无法升级——所以要小心不要丢失它！

哦，还有一件需要注意的事情是，大多数情况下，你会想要使用一个单一的密钥库文件来登录到你个人或公司的所有 Android 应用程序。记得你需要向 keytool 实用程序传递一个-alias 标志，以及该别名有自己的密码吗？事实证明，一个密钥库可以有多个别名，你会想为你构建的每个 Android 应用程序创建一个别名。

好的，现在你有了这个`.jks`文件，并且你已经把它存储在一个安全的地方，剩下的过程就相当容易了。

使用 webpack 构建我们的 Android 应用程序，并传递刚刚用来创建`.jks`文件的信息。例如，以下命令用于创建`nStudio`的发布构建：

```ts
npm run build-android-bundle -- --release --keyStorePath ~/path/to/nstudio.jks --keyStorePassword our-pass --keyStoreAlias nstudio --keyStoreAliasPassword our-alias-pass
```

一旦命令运行完成，您将在应用程序的`platforms/android/build/outputs/apk`文件夹中获得一个可发布的`.apk`文件；请注意该文件的位置，因为您将在下一步-在 Google Play 上部署您的应用程序时需要它：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00078.jpeg)

# 上传到 Google Play

Google Play 是 Android 用户查找和安装应用的地方，而 Google Play 开发者控制台（[`play.google.com/apps/publish/`](https://play.google.com/apps/publish/)）是开发人员注册和上传应用供用户使用的地方。

您将首先按名称创建一个新应用，然后将其列出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00079.jpeg)

Android 关于上传应用程序和设置商店列表的文档非常好，因此我们不会在这里重复所有这些信息。相反，我们将提供一些提示，这些提示在将您自己的 NativeScript 应用程序上传到 Google Play 时可能会有所帮助。

在 Google Play 开发者控制台的商店列表选项卡中，您将需要提供应用程序运行时的至少两个屏幕截图，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00080.jpeg)

使用`tns run android --emulator`命令在 Android 虚拟设备（AVD）上启动您的应用。Android AVD 具有内置的方法，可以使用模拟器侧边栏中的小相机图标来截取屏幕截图。

使用此按钮来截取应用程序中最重要的屏幕的几个屏幕截图，图像文件本身将出现在您的桌面上。此外，还需要一个 1024 x 500 的特色图像文件，它将显示在您商店列表的顶部，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00081.jpeg)

尽管在上述屏幕截图中没有显示，但我们建议您使用 DaVinci（[`www.davinciapps.com`](https://www.davinciapps.com)）等服务为您的屏幕截图增添一些特色，并将它们制作成一个小教程，展示您的应用的功能。

# APK

Google Play 开发者控制台的应用发布部分是您上传在本章前一步骤中生成的`.apk`文件的地方。

当您查看应用发布部分时，您可能会看到有关选择加入 Google Play 应用签名的提及。最好现在选择加入，而不是以后。一旦您选择加入，它将显示为已启用：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00082.jpeg)

然后，您可以继续上传应用程序的 apk 文件到`platforms/android/build/outputs/apk`文件夹中。

一旦您上传了您的 APK 文件，您应该在同一页上看到它列出，您可以在那里为上传的版本输入多种语言的发布说明：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00083.jpeg)

在您点击该页面上的“保存”按钮后，您可能会想返回到商店列表部分，完成填写您应用的所有信息。一旦一切就绪，您就可以提交您的应用了。Android 应用的审核通常需要几个小时，除非 Google 标记出任何问题，您的应用应该在 Google Play 上可用，大约需要半天左右。

# 总结

哇哦！我们在 Apple App Store 和 Google Play 商店中从*零到发布*构建了一个应用。这是一次充满曲折和转折的冒险。我们真诚地希望这为您深入了解了 NativeScript 和 Angular 应用开发，并为那些好奇的人解开了这个激动人心的技术堆栈的任何领域。

NativeScript 和 Angular 都有蓬勃发展的全球社区，我们鼓励您参与其中，分享您的经验，并与他人分享您和您的团队可能正在进行的所有激动人心的项目。永远不要犹豫寻求帮助，因为我们都对这两种技术的热爱和钦佩负有责任。

还有一些其他有用的资源可以查看：

+   [`forum.nativescript.org`](http://forum.nativescript.org)

+   [`nativescript.rocks`](http://nativescript.rocks)

当然还要了解文档！

[`docs.nativescript.org/angular/start/introduction.html`](http://docs.nativescript.org/angular/start/introduction.html)

干杯！
