# Angular NativeScript 移动开发（三）

> 原文：[`zh.annas-archive.org/md5/289e6d84a31dea4e7c2b3cd2576adf55`](https://zh.annas-archive.org/md5/289e6d84a31dea4e7c2b3cd2576adf55)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：赋予你的视图更多力量

Angular 和 NativeScript 的结合在移动开发中非常有趣，而且功能强大。无论您需要提供服务以与移动设备的硬件功能进行交互，比如音频录制，或者通过引人入胜的视图增强您的应用的可用性，NativeScript for Angular 都提供了令人兴奋的机会。

让我们继续使用我们在前一章中开发的几个概念，为我们的曲目提供一个替代的丰富视图，同时重用我们到目前为止所涵盖的一切，以及一些新的技巧。

在本章中，我们将涵盖以下主题：

+   使用`ListView`和`templateSelector`进行多个项目行模板

+   使用`ListView`处理行模板的更改以及何时/如何刷新它们

+   使用`NativeScriptFormsModule`通过`ngModel`数据绑定

+   利用共享的单例服务在多个模块之间共享状态

+   在存储之前对数据进行序列化，并在从持久状态检索时进行水合处理

+   利用和重用 Angular 指令来丰富 NativeScript 滑块的独特特性

# 使用 NativeScript 的 ListView 进行多个项目模板

在整个第八章中，*构建音频录制器*，我们设计了一个双重用途的自定义 NativeScript 波形视图，它利用了 iOS 和 Android 的各种本机库，特别是为了丰富我们的作曲曲目列表视图。让我们继续重用我们多才多艺的波形视图来展示我们的曲目列表视图。这也将为我们提供一种显示混音滑块控件（在音频制作和声音工程中通常称为淡入淡出器）的方法，以便用户可以调整每个曲目在整体作品中的音量水平。让我们设置我们的`TrackListComponent`的`ListView`，使用户能够以两种不同的方式查看和处理他们的曲目，每种方式都有其独特的实用性。与此同时，我们还将利用这个机会最终连接我们曲目上的`mute`开关。

让我们对`app/modules/player/components/track-list/track-list.component.html`进行以下修改：

```ts
<ListView #listview [items]="tracks | orderBy: 'order'" class="list-group" 
  [itemTemplateSelector]="templateSelector">
  <ng-template let-track="item" nsTemplateKey="default">
    <GridLayout rows="auto" columns="100,*,100" class="list-group-item" 
      [class.muted]="track.mute">
      <Button text="Record" (tap)="record(track)" row="0" col="0" class="c-ruby"></Button>
      <Label [text]="track.name" row="0" col="1" class="h2"></Label>
      <Switch row="0" col="2" class="switch" [(ngModel)]="track.mute"></Switch>
    </GridLayout>
  </ng-template>

  <ng-template let-track="item" nsTemplateKey="waveform">
    <AbsoluteLayout [class.muted]="track.mute">
      <Waveform class="waveform w-full" top="0" left="0" height="80"
        [model]="track.model"
        type="file"
        plotColor="#888703"
        fill="true"
        mirror="true"
        plotType="buffer"></Waveform>

      <Label [text]="track.name" row="0" col="1" class="h3 track-name-float"
        top="5" left="20"></Label>
      <Slider slim-slider="fader.png" minValue="0" maxValue="1" 
        width="94%" top="50" left="0"
        [(ngModel)]="track.volume" class="slider fader"></Slider>
    </AbsoluteLayout>
  </ng-template>
</ListView>
```

这里发生了很多有趣的事情。首先，`[itemTemplateSelector]="templateSelector"`提供了在运行时更改我们的`ListView`项目行的能力。`templateSelector`函数的结果应该是一个字符串，与任何 ng-template 的`ngTemplateKey`属性提供的值匹配。为了使所有这些工作，我们需要几件事情，首先是具有通过`#listview`和`ViewChild`访问`ListView`的`Component`：

```ts
// angular
import { Component, Input, ViewChild, ElementRef } from '@angular/core';
import { Router } from '@angular/router';

// nativescript
import { ListView } from 'ui/list-view';

// app
import { ITrack } from '../../../shared/models';
import { AuthService, DialogService } from '../../../core/services';
import { PlayerService } from '../../services/player.service';

@Component({
 moduleId: module.id,
 selector: 'track-list',
 templateUrl: 'track-list.component.html',
})
export class TrackListComponent {

  public templateSelector: Function;
  @Input() tracks: Array<ITrack>;
  @ViewChild('listview') _listviewRef: ElementRef;
 private _listview: ListView;
 private _sub: any;

  constructor(
    private authService: AuthService,
    private dialogService: DialogService,
    private router: Router,
    private playerService: PlayerService
  ) { 
    this.templateSelector = this._templateSelector.bind(this);
  }

  ngOnInit() {
 this._sub = this.playerService.trackListViewChange$.subscribe(() => {      // since this involves our templateSelector, ensure ListView knows about it
      // refresh list
 this._listview.refresh();
 });
 }

 ngAfterViewInit() {
 this._listview = <ListView>this._listviewRef.nativeElement;
 }

 private _templateSelector(item: ITrack, index: number, items: ITrack[]) {
 return this.playerService.trackListViewType;
 }
  ...
```

我们设置了一个`ViewChild`来保留对我们的`ListView`的引用，稍后我们将使用它来调用`this._listview.refresh()`。当我们需要`ListView`在更改后更新显示时，这在 Angular 中是必需的。第一个惊喜可能是注入`PlayerService`，第二个可能是`this.templateSelector = this._templateSelector.bind(this)`。`templateSelector`绑定不是作用域绑定的，由于我们需要它从我们的`this.playerService`返回一个属性引用，我们确保它正确地绑定到`Component`的作用域，通过绑定一个`Function`引用。在这一点上，我们将使用`PlayerService`作为一个通道，以帮助从`MixerModule`中的`ActionBarComponent`传递状态。

这个例子展示了服务如何帮助在整个应用程序中传递状态。然而，通过利用`ngrx`来帮助减少交织的依赖关系并解锁具有 Redux 风格架构的纯响应式设置，这种实践可以得到极大的改进。@ngrx 增强功能将在第十章中进行介绍，*@ngrx/store + @ngrx/effects for State Management*。

我们的 View Toggle 按钮将在`ActionBar`（在`MixerModule`中），我们将希望在那里点击以切换我们的`ListView`，它位于我们的`PlayerModule`内。`PlayerService`目前是一个单例（由`CoreModule`提供），并且在整个应用程序中共享，因此它是一个完美的候选者来帮助这里。让我们首先查看`app/modules/mixer/components/action-bar/action-bar.component.ios.html`中的`ActionBarComponent`的更改：

```ts
<ActionBar [title]="title" class="action-bar">
  <ActionItem nsRouterLink="/mixer/home">
    <Button text="List" class="action-item"></Button>
  </ActionItem>
  <ActionItem (tap)="toggleList()" ios.position="right">
 <Button [text]="toggleListText" class="action-item"></Button>
 </ActionItem>
  <ActionItem (tap)="record()" ios.position="right">
    <Button text="Record" class="action-item"></Button>
  </ActionItem>
</ActionBar>
```

然后，我们将查看`app/modules/mixer/components/action-bar/action-bar.component.android.html`中的更改：

```ts
<ActionBar class="action-bar">
  <GridLayout rows="auto" columns="auto,*,auto,auto" class="action-bar">
    <Button text="List" nsRouterLink="/mixer/home" 
      class="action-item" row="0" col="0"></Button>
    <Label [text]="title" class="action-bar-title text-center" row="0" col="1"></Label>
    <Button [text]="toggleListText" (tap)="toggleList()" 
 class="action-item" row="0" col="2"></Button>
    <Button text="Record" (tap)="record()" 
      class="action-item" row="0" col="3"></Button>
  </GridLayout>
</ActionBar>
```

我们还将查看`Component`中的更改：

```ts
...
import { PlayerService } from '../../../player/services/player.service';

@Component({
  moduleId: module.id,
  selector: 'action-bar',
  templateUrl: 'action-bar.component.html'
})
export class ActionBarComponent {
  ...
  public toggleListText: string = 'Waveform';

  constructor(
    private router: RouterExtensions,
    private playerService: PlayerService
  ) { }
  ...
  public toggleList() {
    // later we can use icons, using labels for now let type = this.playerService.trackListViewType === 'default' ? 'waveform' : 'default';
    this.playerService.trackListViewType = type;
    this.toggleListText = type === 'default' ? 'Waveform' : 'Default';
 }
}
```

正如你所看到的，我们在`ActionBar`中添加了一个按钮，它将根据其状态使用标签`Waveform`或`Default`。然后，我们使用`PlayerService`来修改一个新的 setter，`**this.playerService.trackListViewType** **=** **type**`。现在让我们来看看`app/modules/player/services/player.service.ts`：

```ts
...
@Injectable()
export class PlayerService {
  ...
  // communicate state changes from ActionBar to anything else
  public trackListViewChange$: Subject<string> = new Subject(); ... public get trackListViewType() {
    return this._trackListViewType;
  }

  public set trackListViewType(value: string) {
    this._trackListViewType = value;
    this.trackListViewChange$.next(value);
  } ...
```

这完成了任务。

如前所述，我们将在下一章中通过 ngrx 改进这个设置，这是关于改进和简化我们处理应用程序状态的方式。

还有一些事情我们需要做，以确保我们所有的新添加都能正常工作。首先，`[(ngModel)]`绑定将完全无法工作，如果没有`NativeScriptFormsModule`。

如果您在组件的视图中使用`ngModel`绑定，您必须确保声明您的`Component`的模块导入了`NativeScriptFormsModule`。如果它使用`SharedModule`，请确保`SharedModule`导入和导出`NativeScriptFormsModule`。

让我们将前面提到的模块添加到我们的`SharedModule`中，这样我们所有的模块都可以在需要的地方使用`ngModel`：

```ts
...
import { NativeScriptFormsModule } from 'nativescript-angular/forms'; 
...
@NgModule({
  imports: [
    NativeScriptModule, 
    NativeScriptRouterModule,
    NativeScriptFormsModule
  ],
  ...
  exports: [
    NativeScriptModule,
    NativeScriptRouterModule,
    NativeScriptFormsModule,
    ...PIPES
  ]
})
export class SharedModule {}
```

我们现在需要每个音轨的静音和音量属性的更改来通知我们的音频播放器。这涉及轻微更改我们的`TrackModel`以适应这个新功能；为此，打开`app/modules/shared/models/track.model.ts`：

```ts
import { BehaviorSubject } from 'rxjs/BehaviorSubject';
...
export class TrackModel implements ITrack {
  public id: number;
  public filepath: string;
  public name: string;
  public order: number;
  public model: any;

  public volume$: BehaviorSubject<number>;

  private _volume: number = 1; // default full volume
  private _mute: boolean;
  private _origVolume: number; // return to after unmute

  constructor(model?: ITrack) {
    this.volume$ = new BehaviorSubject(this._volume);
    ...
  }

  public set mute(value: boolean) {
 this._mute = value;
 if (this._mute) {
 this._origVolume = this._volume;
 this.volume = 0;
 } else {
 this.volume = this._origVolume;
 }
 }

 public get mute() {
 return this._mute;
 }

 public set volume(value: number) {
 this._volume = value;
 this.volume$.next(this._volume);
 if (this._volume > 0 && this._mute) {
      // if just increasing volume from a muted state
      // ensure it's unmuted
 this._origVolume = this._volume;
 this._mute = false;
 }
 }

 public get volume() {
 return this._volume;
 }
}
```

现在我们需要修改我们的`TrackPlayerModel`，以配合这些新功能一起工作。之前，我们只保留了`trackId`；然而，有了这个新添加，保留整个`TrackModel`对象的引用会很有帮助，所以打开`app/modules/shared/models/track-player.model.ts`并进行以下更改：

```ts
...
import { Subscription } from 'rxjs/Subscription';
...
interface ITrackPlayer {
  track: TrackModel; // was trackId only
  duration: number;
  readonly player: TNSPlayer;
}
...
export class TrackPlayerModel implements ITrackPlayer {
  public track: TrackModel;
  ...
  private _sub: Subscription;
  ...
  public load(track: TrackModel, complete: Function, error: Function): Promise<number> {
    return new Promise((resolve, reject) => {
      this.track = track;

      this._player.initFromFile({
        ...
      }).then(() => {
        ...
        // if reloading track, clear subscription before subscribing again
        if (this._sub) this._sub.unsubscribe();
 this._sub = this.track.volume$.subscribe((value) => {
 if (this._player) {
 // react to track model property changes
 this._player.volume = value;
 }
 });
      }, reject);
    });
  }
  ...
  public cleanup() {
    // cleanup and dispose player
    if (this.player) this.player.dispose();
    if (this._sub) this._sub.unsubscribe(); 
  }
  ...
```

我们的音频播放器现在可以通过观察`volume$`主题可观察对象来对每个音轨通过数据绑定进行的音量更改做出反应。由于静音实质上只需要修改播放器的音量，我们确保相应地更新音量，并在打开/关闭静音时保持原始音量，因此任何自定义音量设置都将被保留。

我们对轨道的新丰富视图包括可重复使用的波形视图，但这一次使用`type="file"`，因为这将使音频文件的静态波形得以呈现，以便我们可以*看到*我们的音频。我们还提供了调整每个轨道音量（混音控制）的能力，并将标签浮动到左上角，以便用户仍然知道是什么。这一切都是通过利用`AbsoluteLayout`容器完成的，这允许我们重叠组件并手动将它们定位在彼此之上。

# 对数据进行持久化序列化，并在检索时重新注入

这一切都非常顺利，然而，我们引入了一个问题。我们的`MixerService`提供了保存所有轨道的作品的能力。然而，现在轨道包含了诸如可观察对象甚至具有 getter 和 setter 的私有引用等复杂对象。

在持久化数据时，您通常会希望使用`JSON.stringify`对对象进行序列化，以便在存储它们时可以稍后检索并将其转化为更复杂的模型。

实际上，如果您现在尝试使用`JSON.stringify`处理我们的`TrackModel`，它将失败，因为您无法对某些结构进行字符串化。因此，我们现在需要一种在存储数据之前对数据进行序列化的方法，以及一种在检索数据时重新注入数据以恢复我们更复杂模型的方法。让我们对我们的`MixerService`进行一些更改以解决这个问题。打开`app/modules/mixer/services/mixer.service.ts`并进行以下更改：

```ts
// nativescript
import { knownFolders, path } from 'file-system';
...
@Injectable()
export class MixerService {

  public list: Array<IComposition>;

  constructor(
    private databaseService: DatabaseService,
    private dialogService: DialogService
  ) {
    // restore with saved compositions or demo list
    this.list = this._hydrateList(this._savedCompositions() || this._demoComposition());
  }
  ...
  private _saveList() {
    this.databaseService.setItem(DatabaseService.KEYS.compositions, this._serializeList());
  }

  private _serializeList() {
 let serialized = [];
 for (let comp of this.list) {
 let composition: any = Object.assign({}, comp);
 composition.tracks = [];
 for (let track of comp.tracks) {
 let serializedTrack = {};
 for (let key in track) {
          // ignore observable, private properties and waveform model (redundant)
          // properties are restored upon hydration
 if (!key.includes('_') && !key.includes('$') && key != 'model') {
 serializedTrack[key] = track[key];
 }
 }
 composition.tracks.push(serializedTrack);
 }
      // serialized composition
 serialized.push(composition);
 }
 return serialized;
 }

 private _hydrateList(list: Array<IComposition>) {
 for (let c = 0; c < list.length; c++) {
 let comp = new CompositionModel(list[c]);
 for (let i = 0; i < comp.tracks.length; i++) {
 comp.tracks[i] = new TrackModel(comp.tracks[i]);
        // for waveform
 (<any>comp.tracks[i]).model = {
          // fix is only for demo tracks since they use files from app folder
 target: fixAppLocal(comp.tracks[i].filepath)
 };
 }
 // ensure list ref is updated to use hydrated model
 list[c] = comp;
 }
 return list;
 }
  ...
}

const fixAppLocal = function (filepath: string) {
 if (filepath.indexOf('~/') === 0) {    // needs to be absolute path and not ~/ app local shorthand
 return path.join(knownFolders.currentApp().path, filepath.replace('~/', ''));
 }
 return filepath;
}
```

现在，我们将确保每当我们的作品保存时，它都会被正确序列化为安全且更简化的形式，这可以通过`JSON.stringify`进行处理。然后，在从持久存储中检索数据时（在这种情况下，通过 NativeScript 的应用程序设置模块在我们的`DatabaseService`的幕后使用；这在第二章中有所涵盖，*特性模块*），我们将数据重新注入到我们的模型中，这将使用我们的可观察属性丰富数据。

# 利用 Angular 指令丰富 NativeScript 滑块的独特特性

对于每个轨道混音器（也称为我们的混音/音量控制），实际上渲染一个看起来像混音旋钮的控制旋钮会很好，以便清楚地表明这些滑块是混音旋钮，不会被误认为是该轨道的播放。我们可以创建一个用于这些滑块的图形，它将如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00042.jpeg)

对于 iOS，我们还希望有一个按下/高亮状态，这样当用户按下淡入淡出时，可用性会很好：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00043.jpeg)

现在我们可以创建每个文件的两个版本，并将它们放入`app/App_Resources/iOS`；原始文件将是 100x48 用于标准分辨率，然后对于 iPhone Plus 及以上，我们将有一个 150x72 的@3x 版本（基本上是标准 48 高度再加上 24）：

+   `fader-down.png`

+   `fader-down@3x.png`

+   `fader.png`

+   `fader@3x.png`

现在我们可以重用我们的`SlimSliderDirective`（目前用于自定义穿梭滑块的外观）并提供一个输入，以便我们可以提供应用资源中要用于拇指的文件的名称。

打开`app/modules/player/directives/slider.directive.ios.ts`并进行以下修改：

```ts
import { Directive, ElementRef, Input } from '@angular/core';

@Directive({
  selector: '[slim-slider]'
})
export class SlimSliderDirective {
  @Input('slim-slider') imageName: string;

  constructor(private el: ElementRef) { } 

  ngAfterViewInit() {
    let uiSlider = <UISlider>this.el.nativeElement.ios;
    if (this.imageName) {
 uiSlider.setThumbImageForState(
 UIImage.imageNamed(this.imageName), UIControlState.Normal);
      // assume highlighted state always suffixed with '-down'
      let imgParts = this.imageName.split('.');
 let downImg = `${imgParts[0]}-down.${imgParts[1]}`;
 uiSlider.setThumbImageForState(
 UIImage.imageNamed(downImg), UIControlState.Highlighted);
    } else {
      // used for shuttle control
      uiSlider.userInteractionEnabled = false;
      uiSlider.setThumbImageForState(UIImage.new(), UIControlState.Normal);
    }
  }
}

```

这使我们能够在组件本身上指定要用作`Slider`拇指的文件名：

```ts
<Slider slim-slider="fader.png" minValue="0" maxValue="1" 
  width="94%" top="50" left="0"
  [(ngModel)]="track.volume" class="slider fader"></Slider>
```

有了这个，当轨道混音视图切换打开时，我们现在可以为 iOS 定制这些整洁的淡入淡出控件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00044.jpeg)

# Android 的图形和资源处理

现在，让我们也为 Android 处理一下。我们首先将我们标准的 48 高度淡入淡出图形复制到 app/App_Resources/Android/drawable-hdpi 文件夹中。然后我们可以创建这个图形的适当分辨率，并将其复制到各种分辨率相关的文件夹中。要记住的一件事是，Android 不像 iOS 那样使用“@3x”后缀标识符，所以我们只需将所有这些命名为“fader.png”。这是我们图形在一个分辨率相关（在这种情况下是 hdpi，处理“高密度”屏幕分辨率）文件夹中的视图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00045.jpeg)

我们现在可以使用拇指图像处理自定义我们的 Android 滑块指令，打开`app/modules/player/directives/slider.directive.android.ts`：

```ts
import { Directive, ElementRef, Input } from '@angular/core';
import { fromResource } from 'image-source';
import { getNativeApplication } from 'application';

let application: android.app.Application;
let resources: android.content.res.Resources;

const getApplication = function () {
 if (!application) {
 application = (<android.app.Application>getNativeApplication());
 }
 return application;
}

const getResources = function () {
 if (!resources) {
 resources = getApplication().getResources();
 }
 return resources;
}

@Directive({
 selector: '[slim-slider]'
})
export class SlimSliderDirective {
  @Input('slim-slider') imageName: string;
 private _thumb: android.graphics.drawable.BitmapDrawable;

  constructor(private el: ElementRef) { 
    el.nativeElement[(<any>slider).colorProperty.setNative] = function (v) {
// ignore the NativeScript default color setter of this slider
 };
  }

  ngAfterViewInit() {
    let seekBar = <android.widget.SeekBar>this.el.nativeElement.android;
    if (this.imageName) {
 if (!seekBar) {
        // part of view toggle - grab on next tick
        // this helps ensure the seekBar instance can be accessed properly
        // since this may fire amidst the view toggle switching on our tracks
        setTimeout(() => {
 seekBar = <android.widget.SeekBar>this.el.nativeElement.android;
 this._addThumbImg(seekBar);
 });
 } else {
 this._addThumbImg(seekBar);
 }
    } else {
      // seekBar.setEnabled(false);
      seekBar.setOnTouchListener(new android.view.View.OnTouchListener({
        onTouch(view, event) {
          return true;
        }
      }));
      seekBar.getThumb().mutate().setAlpha(0);
    }
  }

  private _addThumbImg(seekBar: android.widget.SeekBar) {
 if (!this._thumb) {
 let imgParts = this.imageName.split('.');
 let name = imgParts[0];
 const res = getResources();
 if (res) {
 const identifier: number = res.getIdentifier(
 name, 'drawable',  getApplication().getPackageName());
 if (0 < identifier) {
          // Load BitmapDrawable with getDrawable to make use of Android internal caching
 this._thumb = <android.graphics.drawable.BitmapDrawable>res.getDrawable(identifier);
 }
 }
 }
    if (this._thumb) {
 seekBar.setThumb(this._thumb);
 seekBar.getThumb().clearColorFilter();
 if (android.os.Build.VERSION.SDK_INT >= 21) {
 (<any>seekBar).setSplitTrack(false);
 }
 }
 }
}
```

上面 Android 实现中最不寻常、也许令人惊讶的一个方面是这个：

```ts
constructor(private el: ElementRef) { 
  el.nativeElement[(<any>slider).colorProperty.setNative] = function (v) {
    // ignore the NativeScript color setter of the slider
  };
}
```

通常情况下，您可以很容易地重用和扩展 NativeScript 中的控件。然而，这是一个例外情况，其中默认的 NativeScript 滑块控件的默认设置器实际上只会在 Android 上给我们带来问题。默认的设置器将尝试将滑块的颜色设置为蓝色，并进行混合处理。当它在滑块上设置这个标志时，我们设置的任何图形形状都会被设置为全蓝色。因此，为了使我们的滑块类能够处理自定义图形，我们必须消除控件上的默认滑块颜色设置器。我们通过附加一个新的“颜色”设置器来控制这一点，这个设置器实际上什么都不做。这样，当 NativeScript 框架在初始化或重置控件时尝试设置默认颜色时，什么都不会发生，从而使我们完全控制发生的事情。作为一种预防措施，在`_addThumbImg`方法的末尾，我们还调用`seekBar.getThumb().clearColorFilter();`以确保在我们能够消除默认颜色设置之前，任何潜在的颜色过滤器都被撤消。

最后，当我们的音轨列表视图切换到混音模式时，我们可以自定义每个音轨显示的音频波形中使用的颜色。由于 Android 的波形插件利用了应用程序的颜色资源，我们可以在 app/App_Resources/Android/values/colors.xml 中添加插件文档中找到的适当命名的属性，并且相同的颜色也应该复制到 app/App_Resources/Android/values-v21/colors.xml 中：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00046.jpeg)

这样，我们现在为 Android 的文件波形显示在混音模式下提供了自定义样式：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00047.jpeg)

# 总结

我们希望为您提供一些额外的好东西，以配合您在第三部分学习到的丰富内容；希望您喜欢！在许多情况下，使用`ListView`的多个项目行模板可能非常方便，但希望这将为您提供工具，让您知道如何使其为您和您的应用程序工作。

数据持久性的特殊考虑因素对于任何引人入胜的应用程序都是一个重要因素，因此我们在存储数据之前查看了数据序列化以及在恢复数据时对数据进行水合处理。

最后，我们将进一步丰富我们的视图组件，使用更多的 Angular 指令优点。 随着第三部分的完成，我们现在已经完成了本书的核心能力和功能集。 但是，我们的应用程序还远未完成。 本书中介绍的开发工作流程和流程是我们为任何构建的应用程序带来的典型开发周期。 我们将在第十四章中涵盖改进我们的架构和进一步完善我们的应用程序，以准备通过 Google Play 和 App Store 进行公开发布，*使用 webpack 打包进行部署准备*。

让我们现在开始通过在第十章中集成`ngrx`来改进我们应用程序的状态处理，*@ngrx/store + @ngrx/effects 用于状态管理*。 值得一提的是，使用 Redux 风格的架构是在构建应用程序之前更好地做出的决定，就像我们在这里所做的那样。 但是，这并不一定是关键的，也不是强制性的，因此，我们希望构建应用程序时将其排除在外，以显示应用程序基本上运行良好。现在，我们将继续进行工作，以展示您可以通过它获得的各种优势。


# 第十章：@ngrx/store + @ngrx/effects 用于状态管理

随着应用程序随着时间的推移而扩展，管理任何应用程序中的状态可能会变得麻烦。我们希望对应用程序行为的可预测性有充分的信心，并且掌握其状态是获得这种信心的关键。

状态可以广义地定义为某人或某物在特定时间的特定状态。就我们的应用程序而言，状态可以包括我们的播放器是否正在播放，录音机是否正在录音，以及曲目列表 UI 是否处于混音模式。

将状态存储在一个地方可以让您在任何给定时刻准确知道应用程序的状态。没有单一的存储，通常会导致状态分散在不同的组件和服务中，这往往会导致随着功能的构建而产生两个或更多不同版本的状态。随着不同的功能需要相互交互，这种笨重的状态增长变得更加麻烦，这些功能可能或可能不一定依赖于彼此。

在本章中，我们将涵盖以下主题：

+   理解 Redux 是什么

+   理解 ngrx 是什么以及它与 Redux 的关系

+   为应用程序定义状态

+   集成@ngrx/store 来管理状态

+   理解@ngrx/effects 是什么

+   集成副作用以帮助我们的状态管理

+   从*不活跃到*响应式*的代码库（Mike Ryan/Brandon Roberts^(TM)）

# 理解 Redux 并集成@ngrx/store

Redux 是一个开源库，它将自己定义为 JavaScript 应用程序的可预测状态容器。这些概念并不是全新的，但细节是由 Dan Abramov 在 2015 年开发的，他受到了 Facebook 的 Flux 和函数式编程语言 Elm 的影响。它很快在 React 社区中变得流行，因为它在 Facebook 中被广泛使用。

我们不想重新定义 Redux 是什么，所以我们将直接引用 Redux 仓库（[`github.com/reactjs/redux`](https://github.com/reactjs/redux)）中的内容：

您的应用程序的整个状态存储在单个*store*内的对象树中。

改变状态树的唯一方法是发出一个*action*，描述发生了什么。

为了指定操作如何转换状态树，您需要编写纯*reducers*。

就是这样！

这个概念相当简单，而且非常聪明。您对系统发出动作（这些动作是简单的字符串类型对象，带有表示要传递的数据的有效负载），这些动作最终会触发一个减速器（一个纯函数），定义这些动作如何转换状态。

重要的是不要混淆转换和突变。Redux 的一个基本概念是所有状态都是**不可变的**；因此，每个减速器都是一个**纯**函数。

纯函数在给定相同参数的情况下总是返回相同的结果。它的执行不依赖于系统作为整体的状态[[`en.wikipedia.org/wiki/Pure_function`](https://en.wikipedia.org/wiki/Pure_function)]。

因此，尽管减速器转换状态，但它不会改变状态。

深入的工程研究已经对变更检测系统以及对象相等性/引用检查在速度上的优势进行了研究，与深度嵌套属性的对象比较检查相比。我们不会详细介绍这一点，但是应用程序数据流的不可变性对于您如何调整其性能有重大影响，特别是关于 Angular。

除了性能增强之外，Redux 的概念进一步增强了整个代码库的解耦，从而减少了分散在各处的各种依赖关系。通过描述我们的应用程序涉及的各种交互的动作的力量，我们不再需要注入显式的服务依赖来执行其 API。相反，我们可以简单地发出动作，Redux 的原则将为我们传播和处理应用程序需求的必要功能，同时保持一个单一可靠的真相来源。

# @ngrx/store 是什么？

在 Angular 的重写过程中（从 1.x 到 2.x+），谷歌的核心团队成员、开发者倡导者 Rob Wormald 开发了**ngrx/store**作为“*由 RxJS 驱动的 Angular 应用程序状态管理[系统]，灵感来自于 Redux。”*该短语中的关键点是“**RxJS**”一词。因此，**ngrx**的名称来源于将“**ng**”（代表 Angular）与“**rx**”（来自**Rx**JS）相结合。这个开源库迅速吸引了像 Mike Ryan、Brian Troncone 和 Brandon Roberts 这样的高素质贡献者，并成为现代 Angular 应用程序的极其智能和强大的状态管理系统。

尽管它受到 Redux 的重大启发并利用了相同的概念，但它在如何连接系统中使 RxJS 成为一等公民方面是独特的不同。它将**Observables**完全贯穿于 Redux 的所有概念中，实现了真正的**响应式**用户界面和应用程序。

如果所有这些概念对你来说都是新的，Brian Troncone 的详细帖子肯定会帮助你更好地理解，因为我们无法在这里涵盖 ngrx 的每个细节。请参阅此帖子：

+   [`gist.github.com/btroncone/a6e4347326749f938510`](https://gist.github.com/btroncone/a6e4347326749f938510)

# 设计状态模型

在集成 ngrx 之前，首先要考虑应用程序中状态的各个方面，以及它们可能涉及的模块。对于我们的应用程序，这是一个合理的起始清单（*此时不打算完整或全面*）：

+   `CoreModule`:

+   `user: any;` 与用户相关的状态：

+   `recentUsername: string`; 最近使用的成功用户名

+   `current: any`; 已认证的用户（如果有的话）

+   `MixerModule`:

+   `mixer: any`: 混音器相关的状态

+   `compositions: Array<IComposition>`; 用户保存的作曲列表

+   `activeComposition: CompositionModel`; 活动的作曲

+   `PlayerModule`:

+   `player: any`; 播放器状态的各个方面。

+   `playing: boolean`; 音频是否正在播放。

+   `duration: number`; 播放的总持续时间。

+   `completed: boolean`; 播放是否达到结尾并已完成。这将有助于区分用户停止播放和播放器因达到结尾而自动停止的区别。

+   `seeking: boolean`; 是否正在进行播放的搜索。

+   `RecorderModule`:

+   `recorder: RecordState`; 用枚举简单表示的录音状态

没有特定的模块，只是我们想要观察的状态：

+   `ui: any`; 用户界面状态

+   `trackListViewType: string`; 曲目列表的当前活动视图切换

这里的关键点是不要担心第一次就完全正确地得到这一点。在首次构建应用程序时很难知道精确的状态模型，而且它很可能会随着时间的推移而稍微改变，这没关系。

我们的应用程序的状态在这个时候更容易知道，因为我们已经构建了一个可工作的应用程序。通常，在构建应用程序之前进行映射会更加困难；然而，同样，不要担心第一次就得到正确！您可以随时进行重构和调整。

让我们把这个状态和 ngrx 一起应用到我们的应用程序中。

# 安装和集成@ngrx/store

我们首先要安装`@ngrx/store`：

```ts
npm i @ngrx/store --save
```

现在，我们可以通过`StoreModule`向我们的应用程序提供单一存储。我们在`CoreModule`中定义了这些初始状态片段，在应用程序启动时可用，而每个延迟加载的功能模块在需要时会添加自己的状态和减速器。

# 提供初始应用程序状态，不包括任何延迟加载的模块状态

我们首先要做的是定义初始应用程序状态，不包括任何延迟加载的功能模块状态。由于我们的`CoreModule`提供了`AuthService`，处理我们的用户，我们将把**user**片段视为应用程序初始状态的基本关键。

特别是，让我们首先定义我们的用户状态的形状。

创建`app/modules/core/states/user.state.ts`：

```ts
export interface IUserState {
  recentUsername?: string;
  current?: any;
  loginCanceled?: boolean;
}

export const userInitialState: IUserState = {};
```

我们的用户状态非常简单。它包含一个`recentUsername`，表示最近成功验证的用户名的字符串（如果用户注销并稍后返回登录，则此信息很有用）。然后，我们有**current**，如果经过身份验证，则表示用户对象，如果没有，则为 null。我们还包括一个`loginCanceled`布尔值，因为我们推测如果我们开始报告状态作为分析数据，这可能对分析用户交互很有用。

围绕身份验证的任何数据点都可能对了解我们应用程序的用户群体至关重要。例如，了解是否要求记录身份验证是否导致取消登录比注册更多，这可能会直接影响用户留存。

为了与本书中的方法保持一致，还要创建`app/modules/core/states/index.ts`：

```ts
export * from './user.state';
```

现在，让我们创建我们的用户动作；创建`app/modules/core/actions/user.action.ts`：

```ts
import { Action } from '@ngrx/store';
import { IUserState } from '../states';

export namespace 

UserActions {
  const CATEGORY: string = 'User';

  export interface IUserActions {
    INIT: 

string;
    LOGIN: string;
    LOGIN_SUCCESS: string;
    LOGIN_CANCELED: string;
    LOGOUT: 

string;
    UPDATED: string;
  }

  export const ActionTypes: IUserActions = {
    INIT:           

`${CATEGORY} Init`,
    LOGIN:          `${CATEGORY} Login`,
    LOGIN_SUCCESS:  `${CATEGORY} Login Success`,
    LOGIN_CANCELED: `${CATEGORY} Login Canceled`,
    LOGOUT:         `${CATEGORY} Logout`,
    UPDATED:        

`${CATEGORY} Updated`
  };

  export class InitAction implements Action {
    type = 

ActionTypes.INIT;
    payload = null;
  }

  export class LoginAction implements Action {
    type 

= ActionTypes.LOGIN;
    constructor(public payload: { msg: string; usernameAttempt?: string}) { }
  }

  export class LoginSuccessAction implements Action {
    type = ActionTypes.LOGIN_SUCCESS;
    constructor

(public payload: any /*user object*/) { }
  }

  export class LoginCanceledAction implements Action {

  type = ActionTypes.LOGIN_CANCELED;
    constructor(public payload?: string /*last attempted username*/) { }

}

  export class LogoutAction implements Action {
    type = ActionTypes.LOGOUT;
    payload = 

null;
  }

  export class UpdatedAction implements Action {
    type = ActionTypes.UPDATED;

constructor(public payload: IUserState) { }
  }

  export type Actions =
    InitAction
    | 

LoginAction
    | LoginSuccessAction
    | LoginCanceledAction
    | LogoutAction
    | 

UpdatedAction;
}
```

然后，按照我们的标准，创建`app/modules/core/actions/index.ts`：

```ts
export * from './user.action';
```

好了，现在那些动作是怎么回事？！这就是我们定义的内容：

+   `INIT`: 在应用程序启动时初始化用户。换句话说，这个动作将用于检查持久性，并在启动时将用户对象恢复到应用程序状态中。

+   `LOGIN`: 开始登录序列。在我们的应用程序中，这将显示登录对话框。

+   `LOGIN_SUCCESS`: 由于登录是异步的，这个动作将在登录完成后触发。

+   `LOGIN_CANCELED`: 如果用户取消登录。

+   `LOGOUT`: 当用户注销时。

+   `已更新`：我们将使用这个简单的动作来更新我们的用户状态。通常不会直接分发，而是将在我们马上创建的 reducer 中使用。

您在这里看到的规范提供了一致和强类型的结构。通过使用命名空间，我们能够使用名称 `UserActions` 唯一标识这组动作，这使得内部命名能够在我们为惰性加载的模块状态创建的许多其他命名空间动作中保持相同，提供了一个很好的标准。`CATEGORY` 是必需的，因为每个动作必须是唯一的，不仅在这组动作中，而且在整个应用程序中。接口在使用我们的动作时提供了良好的智能，除了类型安全性。各种动作类有助于确保所有分发的动作都是新实例，并提供了一种强类型化我们的动作负载的强大方式。这也使得我们的代码易于以后重构。我们结构中的最后一个实用程序是底部的联合类型，它帮助我们的 reducer 确定它应该关注的适用动作。

说到那个 reducer，让我们现在创建它：`app/modules/core/reducers/user.reducer.ts`：

```ts
import { IUserState, userInitialState } from '../states/user.state';
import { UserActions } from 

'../actions/user.action';

export function userReducer(
  state: IUserState = userInitialState,

action: UserActions.Actions
): IUserState {
  switch (action.type) {
    case 

UserActions.ActionTypes.UPDATED:
      return Object.assign({}, state, action.payload);
    default:

return state;
  }
}
```

Reducer 非常简单。如前所述，它是一个纯函数，接受现有状态和一个动作，并返回一个新状态（作为一个新对象，除非它是默认的起始情况）。这保持了不可变性并保持了事物的优雅。`已更新` 动作将始终是任何动作链中的最后一个，最终触发并改变用户状态。在这种情况下，我们将保持简单，并允许我们的 `已更新` 动作是实际改变用户状态的唯一动作。其他动作将建立一个链，它们最终会分发 `已更新`，如果它们需要改变用户状态。基于我们的动作来改变状态，你当然可以在这里设置更多的情况；然而，在我们的应用中，这将是最终改变用户状态的唯一动作。

*动作链？* 什么是 *动作链*？！如果需要，我们是如何将这些动作连接起来相互作用的？

# 安装和集成 @ngrx/effects

不重新定义，让我们直接从存储库（[`github.com/ngrx/effects`](https://github.com/ngrx/effects)）中查看 @ngrx/effects 的描述：

在`@ngrx/effects`中，effects 是 actions 的来源。您可以使用`@Effect()`装饰器来提示服务上的哪些 observables 是 action sources，`@ngrx/effects`会自动合并您的 action 流，让您订阅它们到 store。

为了帮助您编写新的 action sources，`@ngrx/effects`导出了一个 action observable 服务，该服务会发出应用程序中分发的每个 action。

换句话说，我们可以使用 effects 将我们的 actions 链接在一起，以在整个应用程序中提供强大的数据流组合。它们允许我们插入应该在 action 分发之间和状态最终改变之前发生的行为。最常见的用例是处理 HTTP 请求和/或其他异步操作；然而，它们有许多有用的应用。

首先，让我们安装`@ngrx/effects`：

```ts
npm i @ngrx/effects --save
```

现在让我们来看看我们的用户 actions 在 effect 链中是什么样子的。

不过，为了保持与我们的命名结构一致，让我们将`auth.service.ts`重命名为`user.service.ts`。在整个应用程序中保持一致的命名标准会很有帮助。

现在，创建`app/modules/core/effects/user.effect.ts`：

```ts
// angular
import { Injectable } from '@angular/core';

// libs
import { Store, Action } from 

'@ngrx/store';
import { Effect, Actions } from '@ngrx/effects';
import { Observable } from 

'rxjs/Observable';

// module
import { LogService } from '../../core/services/log.service';
import { 

DatabaseService } from '../services/database.service';
import { UserService } from '../services/user.service';
import { UserActions } from '../actions/user.action';

@Injectable()
export class UserEffects {

  @Effect() init$: Observable<Action> = this.actions$
    .ofType(UserActions.ActionTypes.INIT)
    .startWith(new UserActions.InitAction())
    .map(action => {
      const current = 

this.databaseService
        .getItem(DatabaseService.KEYS.currentUser);
      const recentUsername = 

this.databaseService
        .getItem(DatabaseService.KEYS.recentUsername);
      this.log.debug(`Current user: 

`, current || 'Unauthenticated');
        return new UserActions.UpdatedAction({ current, recentUsername });

});

  @Effect() login$: Observable<Action> = this.actions$
    .ofType

(UserActions.ActionTypes.LOGIN)
    .withLatestFrom(this.store)
    .switchMap(([action, state]) => {

  const current = state.user.current;
      if (current) {
        // user already logged in, just fire 

updated
        return Observable.of(
          new UserActions.UpdatedAction({ current })
        );

    } else {
        this._loginPromptMsg = action.payload.msg;
        const usernameAttempt =

action.payload.usernameAttempt
          || state.user.recentUsername;

        return 

Observable.fromPromise(
          this.userService.promptLogin(this._loginPromptMsg, 
          usernameAttempt)

        )
        .map(user => (new UserActions.LoginSuccessAction(user)))
        .catch

(usernameAttempt => Observable.of(
          new UserActions.LoginCanceledAction(usernameAttempt)

));
      }
    });

  @Effect() loginSuccess$: Observable<Action> = this.actions$

.ofType(UserActions.ActionTypes.LOGIN_SUCCESS)
    .map((action) => {
      const user = action.payload;

     const recentUsername = user.username;
      this.databaseService
        .setItem

(DatabaseService.KEYS.currentUser, user);
      this.databaseService
        .setItem

(DatabaseService.KEYS.recentUsername, recentUsername);
      this._loginPromptMsg = null; // clear, no longer 

needed
      return (new UserActions.UpdatedAction({
        current: user,
        recentUsername,

    loginCanceled: false
      }));
    });

  @Effect() loginCancel$ = this.actions$

.ofType(UserActions.ActionTypes.LOGIN_CANCELED)
    .map(action => {
      const usernameAttempt = 

action.payload;
      if (usernameAttempt) {
        // reinitiate sequence, login failed, retry

return new UserActions.LoginAction({
          msg: this._loginPromptMsg,
          usernameAttempt

});
      } else {
        return new UserActions.UpdatedAction({
          loginCanceled: true

});
      }
    });

  @Effect() logout$: Observable<Action> = this.actions$

.ofType(UserActions.ActionTypes.LOGOUT)
    .map(action => {
      this.databaseService

.removeItem(DatabaseService.KEYS.currentUser);
      return new UserActions.UpdatedAction({
        current: 

null
      });
    });

  private _loginPromptMsg: string;

  constructor(
    private 

store: Store<any>,
    private actions$: Actions,
    private log: LogService,
    private 

databaseService: DatabaseService,
    private userService: UserService
  ) { }
}
```

我们已经澄清了关于我们的`UserService`的数据流意图，并将责任委托给了这个 effect 链。这使我们能够以清晰一致的方式组合我们的数据流，具有很大的灵活性和强大的功能。例如，我们的`InitAction`链现在允许我们通过以下方式自动初始化用户：

```ts
.startWith(new UserActions.InitAction())
```

早些时候，我们在服务构造函数中调用了一个私有方法--`this._init()`；然而，现在我们不再需要像那样显式调用，因为 effects 会在模块启动时运行和排队。`.startWith`操作符将使 observable 在一个特定的时间点触发一次（在模块创建时），允许初始化序列在一个特别合适的时间执行，当我们的应用程序正在初始化时。我们的初始化序列与我们之前在服务中处理的相同；然而，这次我们考虑了我们的新的`recentUsername`持久化值（如果存在）。然后，我们用`UserActions.UpdatedAction`结束初始化序列。

```ts
new UserActions.UpdatedAction({ current, recentUsername })
```

请注意，`UserActions.ActionTypes.UPDATED`没有连接到效果链。这是因为在`Action`发生时不应该发生任何副作用。由于没有更多的副作用，可观察序列最终进入具有`switch`语句来处理它的减速器：

```ts
export function userReducer(
  state: IUserState = userInitialState,
  action: UserActions.Actions
): 

IUserState {
  switch (action.type) {
    case UserActions.ActionTypes.UPDATED:

return Object.assign({}, state, action.payload);
    default:
      return state;
  }
}
```

这将采用有效负载（其类型为用户状态的形状，`IUserState`）并覆盖现有状态中的值，以返回全新的用户状态。重要的是，`Object.assign`允许源对象中的任何现有值不被覆盖，除非传入有效负载明确定义。这样一来，只有新的传入有效负载值会反映在我们的状态上，同时保持现有值。

我们的`UserEffect`链的其余部分相当不言自明。主要是处理服务以前处理的大部分内容，除了提示登录对话框，效果链正在利用服务方法来执行。然而，值得一提的是，我们甚至可以完全删除这个服务，因为`promptLogin`方法的内容现在可以直接在我们的效果中执行。

在决定是否应该在您的效果或指定服务中处理更多逻辑时，这实际上取决于个人偏好和/或可扩展性。如果您有相当长的服务逻辑，并且有多个方法来处理逻辑，同时使用效果，创建指定的服务将会有很大帮助。您可以将更多功能扩展到服务中，而不会削弱效果链的清晰度。

最后，使用具有更多逻辑的指定服务进行单元测试将更容易。在这种情况下，我们的逻辑相当简单；然而，出于示例目的以及最佳实践，我们将保留`UserService`。

说到这个，让我们看看我们的`UserService`现在看起来多么简化。

在`app/modules/core/services/user.service.ts`中：

```ts
// angular
import { Injectable } from '@angular/core';

// app
import { DialogService } from 

'./dialog.service';

@Injectable()
export class UserService {

  constructor(

private dialogService: DialogService
  ) { } 

  public promptLogin(msg: string, username: string = ''): 

Promise<any> {
    return new Promise((resolve, reject) => {
      this.dialogService.login(msg, 

username, '').then((input) => {
        if (input.result) { // result will be false when canceled
          if 

(input.userName && input.userName.indexOf('@') > -1) {
            if (input.password) {

    resolve({
                username: input.userName,
                password: input.password

  });
            } else {
              this.dialogService.alert('You must provide a password.')

     .then(reject.bind(this, input.userName));
            }
          } else {
            // reject, 

passing userName back to try again
            this.dialogService.alert('You must provide a valid email 

   address.')
              .then(reject.bind(this, input.userName));
          }
        } else {

     // user chose cancel
          reject(false);
        }
      });
    });
  }
}
```

现在清洁多了。好的，那么我们如何让我们的应用程序知道所有这些新的好处呢？

首先，让我们按照我们的标准之一，在整个核心模块中添加一个索引；添加`app/modules/core/index.ts`：

```ts
export * from './actions';
export * from './effects';
export * from './reducers';
export * from 

'./services';
export * from './states';
export * from './core.module';
```

我们只需导出核心模块现在提供的所有好东西，包括模块本身。

然后，打开`app/modules/core/core.module.ts`来完成我们的连接：

```ts
// nativescript
import { NativeScriptModule } from 'nativescript-angular/nativescript.module'; 
import { 

NativeScriptFormsModule } from 'nativescript-angular/forms'; 
import { NativeScriptHttpModule } from 'nativescript-

angular/http'; 

// angular
import { NgModule, Optional, SkipSelf } from '@angular/core';

// libs
import { StoreModule } from '@ngrx/store';
import { 

EffectsModule } from '@ngrx/effects';

// app
import { UserEffects } from 

'./effects';
import { userReducer } from './reducers';
import { PROVIDERS } from 

'./services';
import { PROVIDERS as MIXER_PROVIDERS } from '../mixer/services';
import { PROVIDERS as 

PLAYER_PROVIDERS } from '../player/services';

const MODULES: any[] = [
  NativeScriptModule,

NativeScriptFormsModule,
  NativeScriptHttpModule
];

@NgModule({
  imports: [

...MODULES,
    // define core app state
    StoreModule.forRoot({
 user: 

userReducer
 }),
    // register core effects

EffectsModule.forRoot([
      UserEffects
    ]), 
  ],
  providers: [

...PROVIDERS,
    ...MIXER_PROVIDERS,
    ...PLAYER_PROVIDERS
  ],
  exports: [
    ...MODULES
  ]
})
export class CoreModule {
  constructor (@Optional() @SkipSelf() parentModule: CoreModule) 

{
    if (parentModule) {
      throw new Error(
        'CoreModule is already loaded. Import it in the 

AppModule only');
    }
  }
}
```

在这里，我们确保定义我们的`user`状态键来使用`userReducer`并将其注册到`StoreModule`。然后我们调用`EffectsModule.forRoot()`，使用一组单例效果提供者进行注册，就像我们的`UserEffects`一样。

现在，让我们看看这如何改进代码库的其余部分，因为我们无疑在一些地方注入了`UserService`（以前名为`AuthService`）。

我们以前在`AppComponent`中注入`AuthService`，以确保在应用程序引导时早早地构建 Angular 的依赖注入，创建我们应用程序所需的必要单例。然而，现在`UserEffects`在引导时自动运行，然后注入（现在更名为）`UserService`，我们不再需要这种愚蠢的必要性，因此，我们可以按照以下方式更新`AppComponent`：

```ts
@Component({
  moduleId: module.id,
  selector: 'my-app',
  templateUrl: 'app.component.html',
})
export class AppComponent {

  constructor() { // we removed AuthService (UserService) here  
```

我们的代码库现在变得更加智能和精简。让我们继续看看 ngrx 集成的其他好处。

打开`app/auth-guard.service.ts`，我们现在可以进行以下简化：

```ts
import { Injectable } from '@angular/core';
import { Route, CanActivate, CanLoad } from 

'@angular/router';

// libs
import { Store } from '@ngrx/store';
import { Subscription } from 'rxjs/Subscription';

// app
import { IUserState, 

UserActions } from '../modules/core';

@Injectable()
export class AuthGuard implements 

CanActivate, CanLoad {

  private _sub: Subscription;

  constructor(private 

store: Store<any>) { }

  canActivate(): Promise<boolean> {
    return new Promise

((resolve, reject) => {
      this.store.dispatch(
 new 

UserActions.LoginAction({ msg: 'Authenticate to record.' })
 );
 this._sub = this.store.select(s => s.user).subscribe((state: 
      IUserState) => {
 if (state.current) {
 this._reset();
 resolve

(true);
 } else if (state.loginCanceled) {
 this._reset

();
 resolve(false);
 }
 });
    });
  }

  canLoad(route: Route): Promise<boolean> {
    // reuse same 

logic to activate
    return this.canActivate();
  }

  private _reset() {
 if (this._sub) this._sub.unsubscribe();
 }
}
```

激活`/record`路由时，我们每次都会分派`LoginAction`，因为我们需要经过身份验证的用户才能使用录制功能。我们的登录效果链会正确处理用户是否已经经过身份验证，所以我们只需要设置我们的状态订阅以相应地做出反应。

Ngrx 是灵活的，你如何设置你的动作和效果链完全取决于你。

# 提供延迟加载的功能模块状态

现在，我们可以将可扩展的 ngrx 结构构建到我们的各种功能模块中，这将提供状态。从`MixerModule`开始，让我们修改`app/modules/mixer/mixer.module.ts`如下：

```ts
...
// libs
import { StoreModule } from '@ngrx/store';
...

@NgModule({
  imports: [
    PlayerModule,
    SharedModule,

NativeScriptRouterModule.forChild(routes),
    StoreModule.forFeature('mixerModule', {
 mixer: {}     // TODO: add reducer when ready
 })
  ],
  ...
})
export class MixerModule { }
```

在这里，我们正在定义`MixerModule`状态将提供什么。现在，让我们定义它的形状；创建

`app/modules/mixer/states/mixer.state.ts`：

```ts
import { IComposition } from '../../shared/models';

export interface IMixerState {
  compositions?: 

Array<IComposition>;
  activeComposition?: any;
}

export const mixerInitialState: IMixerState = 

{
  compositions: []
};
```

为了与本书中的方法保持一致，还要创建`app/modules/mixer/states/index.ts`：

```ts
export * from './mixer.state';
```

现在，让我们创建我们的混音器动作；创建`app/modules/mixer/actions/mixer.action.ts`：

```ts
import { ViewContainerRef } from '@angular/core';
import { Action } from '@ngrx/store';
import { 

IMixerState } from '../states';
import { IComposition, CompositionModel, TrackModel } from '../../shared/models';

export namespace MixerActions {
  const CATEGORY: string = 'Mixer';

  export interface 

IMixerActions {
    INIT: string;
    ADD: string;
    EDIT: string;
    SAVE: string;
    CANCEL: 

string;
    SELECT: string;
    OPEN_RECORD: string;
    UPDATE: string;
    UPDATED: string;
  }

  export const ActionTypes: IMixerActions = {
    INIT: `${CATEGORY} Init`,
    ADD: `${CATEGORY} 

Add`,
    EDIT: `${CATEGORY} Edit`,
    SAVE: `${CATEGORY} Save`,
    CANCEL: `${CATEGORY} Cancel`,

SELECT: `${CATEGORY} Select`,
    OPEN_RECORD: `${CATEGORY} Open Record`,
    UPDATE: `${CATEGORY} Update`,

   UPDATED: `${CATEGORY} Updated`,
  };

  export class InitAction implements Action {
    type = 

ActionTypes.INIT;
    payload = null;
  }

  export class AddAction implements Action {
    type = 

ActionTypes.ADD;
    payload = null;
  }

  export class EditAction implements Action {
    type = 

ActionTypes.EDIT;
    constructor(public payload: CompositionModel) { }
  }

  export class SaveAction 

implements Action {
    type = ActionTypes.SAVE;
    constructor(public payload?: Array<CompositionModel>) 

{ }
  }

  export class CancelAction implements Action {
    type = ActionTypes.CANCEL;

payload = null;
  }

  export class SelectAction implements Action {
    type = ActionTypes.SELECT;
    constructor(public payload: CompositionModel) { }
  }

  export class OpenRecordAction implements 

Action {
    type = ActionTypes.OPEN_RECORD;
    constructor(public payload?: { 
      vcRef: 

ViewContainerRef, track?: TrackModel 
    }) { }
  }

  export class UpdateAction implements Action 

{
    type = ActionTypes.UPDATE;
    constructor(public payload: CompositionModel) { }
  }

export class UpdatedAction implements Action {
    type = ActionTypes.UPDATED;
    constructor(public payload: 

IMixerState) { }
  }

  export type Actions =
    InitAction
    | AddAction
    | 

EditAction
    | SaveAction
    | CancelAction
    | SelectAction
    | OpenRecordAction
    | 

UpdateAction
    | UpdatedAction;
}
```

与我们的 UserActions 类似，我们还将使用`INIT`动作来自动初始化此状态，使用用户保存的组合（或我们的示例演示组合）进行初始化。以下是一个快速概述：

+   `INIT`：在应用程序启动时初始化混音器。就像我们使用`UserActions`一样，此动作将用于检查持久性并在启动时将任何用户保存的组合恢复到混音器状态。

+   `ADD`：显示添加新组合对话框。

+   `EDIT`：通过提示对话框编辑组合的名称。

+   `SAVE`：保存组合。

+   `CANCEL`：取消任何效果链的一般操作。

+   `SELECT`：选择一个组合。我们将使用这个操作来驱动 Angular 路由到主选定的组合视图。

+   `OPEN_RECORD`：处理准备打开记录视图，包括检查认证、暂停播放（如果正在播放）并在模态框中打开或路由到它。

+   `UPDATE`：启动对组合的更新。

+   `UPDATED`：这通常不会直接分发，而是在效果序列的最后使用，reducer 会最终改变混音器状态。

现在，我们可以创建一个类似于我们用户 reducer 的 reducer：

```ts
import { IMixerState, mixerInitialState } from '../states';
import { MixerActions } from '../actions';

export function mixerReducer(
  state: IMixerState = mixerInitialState,
  action: MixerActions.Actions
): 

IMixerState {
  switch (action.type) {
    case MixerActions.ActionTypes.UPDATED:
      return 

Object.assign({}, state, action.payload);
    default:
      return state;
  }
}
```

之后，让我们在`app/modules/mixer/effects/mixer.effect.ts`中创建我们的`MixerEffects`：

```ts
// angular
import { Injectable, ViewContainerRef } from '@angular/core';

// nativescript
import { RouterExtensions } from 'nativescript-angular/router';

// libs
import { Store, Action } from 

'@ngrx/store';
import { Effect, Actions } from '@ngrx/effects';
import { Observable } from 

'rxjs/Observable';

// module
import { CompositionModel } from '../../shared/models';
import { 

PlayerActions } from '../../player/actions';
import { RecordComponent } from 

'../../recorder/components/record.component';
import { MixerService } from '../services/mixer.service';
import { 

MixerActions } from '../actions';

@Injectable()
export class MixerEffects {

  @Effect() 

init$: Observable<Action> = this.actions$
    .ofType(MixerActions.ActionTypes.INIT)
    .startWith(new 

MixerActions.InitAction())
    .map(action =>
      new MixerActions.UpdatedAction({

compositions: this.mixerService.hydrate(
          this.mixerService.savedCompositions()
          || 

this.mixerService.demoComposition())
      })
    );

  @Effect() add$: Observable<Action> = 

this.actions$
    .ofType(MixerActions.ActionTypes.ADD)
    .withLatestFrom(this.store)
    .switchMap

(([action, state]) =>
      Observable.fromPromise(this.mixerService.add())
        .map(value => {

       if (value.result) {
            let compositions = [...state.mixerModule.mixer.compositions];

let composition = new CompositionModel({
              id: compositions.length + 1,
              name: 

value.text,
              order: compositions.length // next one in line
            });

compositions.push(composition);
            // persist changes
            return new MixerActions.SaveAction

(compositions);
          } else {
            return new MixerActions.CancelAction();
          }

   })
    );

  @Effect() edit$: Observable<Action> = this.actions$
    .ofType

(MixerActions.ActionTypes.EDIT)
    .withLatestFrom(this.store)
    .switchMap(([action, state]) => {

  const composition = action.payload;
      return Observable.fromPromise(this.mixerService.edit(composition.name))
        .map(value => {
          if (value.result) {
            let compositions = 

[...state.mixerModule.mixer.compositions];
            for (let i = 0; i < compositions.length; i++) {

      if (compositions[i].id === composition.id) {
                compositions[i].name = value.text;

    break;
              }
            }
            // persist changes
            return new 

MixerActions.SaveAction(compositions);
          } else {
            return new MixerActions.CancelAction();
          }
        })
      });

  @Effect() update$: Observable<Action> = this.actions

$
    .ofType(MixerActions.ActionTypes.UPDATE)
    .withLatestFrom(this.store)
    .map(([action, state]) 

=> {
      let compositions = [...state.mixerModule.mixer.compositions];
      const composition = 

action.payload;
      for (let i = 0; i < compositions.length; i++) {
        if (compositions[i].id === 

composition.id) {
          compositions[i] = composition;
          break;
        }
      }

 // persist changes
      return new MixerActions.SaveAction(compositions);
    });

  @Effect() 

select$: Observable<Action> = this.actions$
    .ofType(MixerActions.ActionTypes.SELECT)
    .map(action 

=> {
      this.router.navigate(['/mixer', action.payload.id]);
      return new MixerActions.UpdatedAction

({
        activeComposition: action.payload
      });
    });

  @Effect({ dispatch: false }) 

openRecord$: Observable<Action> = this.actions$
    .ofType(MixerActions.ActionTypes.OPEN_RECORD)

.withLatestFrom(this.store)
    // always pause/reset playback before handling
    .do(action => new 

PlayerActions.PauseAction(0))
    .map(([action, state]) => {
      if 

(state.mixerModule.mixer.activeComposition &&
        state.mixerModule.mixer.activeComposition.tracks.length) 

{
        // show record modal but check authentication
        if (state.user.current) {
          if 

(action.payload.track) {
            // rerecording
            this.dialogService
              .confirm

(
                'Are you sure you want to re-record this track?'
              ).then((ok) => {

        if (ok) 
                  this._showRecordModal(
                    action.payload.vcRef, 

            action.payload.track
                  );
              });
          } else {

this._showRecordModal(action.payload.vcRef);
          }
        } else {
          this.store.dispatch(
            new UserActions.LoginToRecordAction(action.payload));
        }
      } else {
        // 

navigate to it
        this.router.navigate(['/record']);
      }
      return action;
    });

  @Effect() save$: Observable<Action> = this.actions$
    .ofType(MixerActions.ActionTypes.SAVE)

.withLatestFrom(this.store)
    .map(([action, state]) => {
      const compositions = action.payload || 
                           state.mixerModule.mixer.compositions;
      // persist
      this.mixerService.save

(compositions);
      return new MixerActions.UpdatedAction({ compositions });
    });

  constructor

(
    private store: Store<any>,
    private actions$: Actions,
    private router: 

RouterExtensions,
    private dialogService: DialogService,
    private mixerService: MixerService
  ) { }

  private _showRecordModal(vcRef: ViewContainerRef, track?: TrackModel) {
    let context: any = { 

isModal: true };
    if (track) {
      // re-recording track
      context.track = track;
    }

  this.dialogService.openModal(
      RecordComponent,
      vcRef,
      context,

'./modules/recorder/recorder.module#RecorderModule'
    );
  }
}
```

可能，最有趣的效果是`openRecord$`链。我们使用`@Effect({ dispatch: false })`来指示它在最后不应该分发任何操作，因为我们使用它来直接执行工作，比如检查用户是否已经认证，或者`activeComposition`是否包含轨道，以有条件地在模态框中或作为路由打开记录视图。我们使用了另一个操作符：

```ts
.do(action => new PlayerActions.PauseAction(0))
```

这使我们能够插入任意操作而不影响事件序列。在这种情况下，我们确保当用户尝试打开记录视图时始终暂停播放（因为他们可能在播放时尝试打开记录视图）。我们在这个链中展示了一些更高级的使用选项，只是为了展示可能性。我们也稍微超前了一点，因为我们还没有展示`PlayerActions`的创建；然而，在本章中我们只会呈现一些亮点。

通过这个效果链，我们可以简化我们的`MixerService`如下：

```ts
...
@Injectable()
export class MixerService {
  ...
  public add() {
    return 

this.dialogService.prompt('Composition name:');
  }

  public edit(name: string) {

return this.dialogService.prompt('Edit name:', name);
  }
  ...
```

我们简化了服务逻辑，将大部分结果处理工作留在了效果链内。您可能决定保留服务更多的逻辑，并保持效果链更简单；然而，我们设计了这个设置作为一个示例，以展示 ngrx 的灵活性。

为了完成我们的懒加载状态处理，请确保这些效果被运行；当`MixerModule`加载时，我们可以对模块进行以下调整：

```ts
...
// libs
import { StoreModule } from '@ngrx/store';
import { EffectsModule } from 

'@ngrx/effects';
...
import { MixerEffects } from './effects';
import 

{ mixerReducer } from './reducers';

@NgModule({
  imports: [
    PlayerModule,

SharedModule,
    NativeScriptRouterModule.forChild(routes),
    // mixer state
    StoreModule.forFeature

('mixerModule', {
      mixer: mixerReducer
    }),
    // mixer effects

EffectsModule.forFeature([
      MixerEffects
    ])
  ],
  ...
})
export 

class MixerModule { }
```

现在，让我们看看这如何改进我们的组件处理，从`app/modules/mixer/components/mixer.component.ts`开始：

```ts
...
export class MixerComponent implements OnInit, OnDestroy {
  ...
  constructor( private store: Store<any>,
    private vcRef: ViewContainerRef  ) { }

  ngOnInit() 

{
    this._sub = this.store.select(s => s.mixerModule.mixer)
 .subscribe

((state: IMixerState) => {
 this.composition = state.activeComposition;
 });
  }

  public record(track?: TrackModel) {

this.store.dispatch(new MixerActions.OpenRecordAction({
 vcRef: this.vcRef,
 track
 }));
  }

  ngOnDestroy() {
 this._sub.unsubscribe();
 }
}
```

这一次，在`ngOnInit`中，我们只需设置组件对我们混音器状态的响应性，将组合设置为`activeComposition`。这保证始终是用户当前选择并正在操作的组合。我们在`record`方法中分派我们的`OpenRecordAction`，传递适当的`ViewContainerRef`和用户是否正在重新录制的轨道。

接下来是简化`app/modules/mixer/components/mix-list.component.ts`：

```ts
// angular
import { Component } from '@angular/core';

// libs
import { Store } from 

'@ngrx/store';
import { Observable } from 'rxjs/Observable';

// app
import { MixerActions } from '../actions';
import { IMixerState } from '../states';

@Component({
  moduleId: module.id,
  selector: 'mix-list',
  templateUrl: 'mix-list.component.html'
})
export class MixListComponent {
  public mixer$: Observable<IMixerState>;

  constructor(private store: Store<any>) {
    this.mixer$ = store.select(s => s.mixerModule.mixer);
  } 

  public add() {
    this.store.dispatch(new MixerActions.AddAction());
  }

  public edit(composition) {
    this.store.dispatch(new MixerActions.EditAction(composition));
  }

  public select(composition) {
    this.store.dispatch(new MixerActions.SelectAction(composition));
  }
}
```

我们已经移除了`MixerService`的注入，并通过设置状态 Observable--`mixer$`--并集成我们的`MixerActions`，使其变得响应式。这减轻了组件的负担，使其更容易测试和维护，因为它不再显式依赖于`MixerService`，以前用于视图绑定。如果我们看一下视图，现在我们可以利用 Angular 的异步管道来通过状态访问用户保存的组合：

```ts
<ActionBar title="Compositions" class="action-bar">
  <ActionItem (tap)="add()" 

ios.position="right">
    <Button text="New" class="action-item"></Button>

</ActionItem>
</ActionBar>
<ListView [items]="(mixer$ | async)?.compositions | 

orderBy: 'order'" class="list-group">
  <ng-template let-composition="item">
    <GridLayout 

rows="auto" columns="100,*,auto" class="list-group-item">
      <Button text="Edit" (tap)="edit(composition)" 

row="0" col="0"></Button>
      <Label [text]="composition.name" (tap)="select(composition)" row="0" 

col="1" class="h2"></Label>
      <Label [text]="composition.tracks.length" row="0" col="2" class="text-

right"></Label>
    </GridLayout>
  </ng-template>
</ListView>
```

根据官方文档：Angular 的异步管道订阅 Observable 或 Promise 并返回它发出的最新值。当发出新值时，异步管道会标记组件以进行更改检查。当组件被销毁时，异步管道会自动取消订阅，以避免潜在的内存泄漏。

这真是非常了不起和非常方便，使我们能够创建高度可维护和灵活的响应式组件。

# 检查代码！自己探索更多

由于我们之前看到的很多内容都是应用于我们代码库的其他部分的相同原则，而不是进一步增加本书的篇幅，我们邀请您在本书附带的代码存储库的同一章节分支中探索其余的 ngrx 集成。

浏览实际代码，运行它，甚至逐步执行它，希望能让您对 ngrx 如何适应您的应用程序以及它可以带来的许多优势有一个扎实的理解。

社区很幸运能有像 Rob Wormald，Mike Ryan，Brian Troncone，Brandon Roberts 等成员，他们帮助使 ngrx 的使用变得如此愉快，因此**非常感谢所有的贡献者**！

# 总结

希望您开始看到在集成 ngrx 时简化和澄清数据流的模式。它有助于减少代码，同时通过为各种操作提供一致的效果链来改进数据流，这些操作可能需要在任何地方发生（从惰性加载的模块或其他地方）。通过减少在整个过程中管理显式注入的依赖项的开销，而是依赖 Store 和 Actions 来启动适当的工作，我们正在增加应用程序的可维护性和可扩展性。最重要的是，它为有效的可测试性铺平了道路，我们将在《第十二章》《单元测试》中进行介绍。

本章突出了将 NativeScript 与 Angular 相结合的额外优势，通过打开与丰富库（如 ngrx）的集成潜力，改进我们的应用程序架构和数据流。

这是一个漫长的过程，我们对接下来的《第十一章》《使用 SASS 进行波兰语》感到非常兴奋。最终，我们准备好了，要打磨我们的应用程序，赋予它特别的火花！
