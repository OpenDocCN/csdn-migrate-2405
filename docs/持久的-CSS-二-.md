# 持久的 CSS（二）

> 原文：[`zh.annas-archive.org/md5/75CD231CF1D89323893E2DE8217A208E`](https://zh.annas-archive.org/md5/75CD231CF1D89323893E2DE8217A208E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：ECSS 方法的工具

在这最后一章中，我们将看一些免费和开源的工具，以便编写合理和可维护的样式表。

在为持久项目编写 CSS 时，用于生成 CSS 的技术应该基本上是无关紧要的。我们应该始终意识到可能会有更好或更有效的工具可用来实现我们的目标，如果可能的话，应该加以采纳。

因此，无论是 Sass、PostCSS、LESS、Stylus、Myth 还是其他任何 CSS 处理器，都不应该成为编写样式表的障碍。如果需要的话，编写的样式表应尽可能容易迁移到另一种元语言。

此外，所采用的 CSS 处理器应该最好能满足整个项目的需求，而不仅仅是个别作者的偏好。也就是说，CSS 处理器应具备一些必要的功能，接下来我们将简要介绍这些功能。

# CSS 处理器的 CSS 要求

我认为 CSS 处理器对于样式表编写是必不可少的。这允许区分*编写*的样式表（作者在其选择的 CSS 处理器中编写的样式表）和*结果*的 CSS（编译和压缩后提供给用户的 CSS）。

尽管声明 CSS 处理器是必不可少的，但所需的功能相当微不足道：

+   **变量**：减少人为错误，如颜色选择和指定常量如网格尺寸

+   **部分文件**：为了方便作者编写与特性分支、模板或逻辑文件相对应的样式表

+   **颜色操作**：允许对上述变量进行一致的操作，例如能够调整颜色的 alpha 通道或轻松调整颜色

+   所有其他能力被认为是非必要的，应根据项目的特定需求进行评估

# 从编写的样式表构建 CSS

需要某种构建系统将编写的样式表编译成纯 CSS。

### 提示

有许多工具可用于执行此任务，例如 Grunt、Gulp 和 Brocolli 等。然而，就像没有普遍*正确*的 CSS 处理器或 CSS 方法论一样，也没有普遍*正确*的构建工具。

除了将编写的样式表编译成 CSS 之外，良好的工具还可以提供进一步的好处。

+   **Linting**：启用代码一致性并防止非工作代码达到部署

+   **Aggressive minification**：重新定位 z-index，将长度值转换为更小的长度值，例如（虽然*1pt*等同于*16px*，但字符数少了一个），合并相似的选择器

+   **Autoprefixer**：启用快速准确的供应商前缀，并防止供应商前缀出现在编写的样式表中

### 提示

对于样式表编写中被认为是必不可少的语法方面的考虑，请参阅第八章，“合理样式表的十诫”。

## 保存编译，ECSS 样式表的旅程

就工具而言，在撰写本文时，我目前使用 Gulp 和 PostCSS 以及其众多插件来编写 ECSS。这是一个运作良好的过程，所以我会在这里简要记录一下。

### 注意

对于非常好奇的人，可以在这里找到更多关于我从 Sass 到 PostCSS 的*经历*（[`benfrain.com/breaking-up-with-sass-postcss/`](https://benfrain.com/breaking-up-with-sass-postcss/)）。

样式表作者将样式表写入一个部分 CSS 文件（带有`*.css`文件扩展名），使用的语法与 Sass 非常相似。

在保存作者样式表时，Gulp watch 任务会注意到文件的更改，并首先运行 linting 任务。然后，如果一切正常，它会将部分作者样式表编译为 CSS 文件，然后自动添加前缀，最后 BrowserSync 将更改的 CSS 直接注入到我正在工作的网页中。通常，在我可以 *Alt* + *Tab* 到浏览器窗口之前，或者甚至在我从文本编辑器移动到浏览器窗口之前，都会创建一个源映射文件，因为一些作者发现在开发者工具中使用源映射更容易进行调试。所有这些都发生在我可以 *Alt* + *Tab* 到浏览器窗口之前，甚至在我可以从文本编辑器移动到浏览器窗口之前。

这是一个演示如何在基于 Gulp 的构建工具中设置 PostCSS 的 `gulpfile.js` 示例：

```css
//PostCSS related
var postcss = require("gulp-postcss");
var postcssImport = require("postcss-import");
var autoprefixer = require("autoprefixer");
var simpleVars = require("postcss-simple-vars");
var mixins = require("postcss-mixins");
var cssnano = require("cssnano");
var reporter = require("postcss-reporter");
var stylelint = require("stylelint");
var stylelinterConfig = require("./stylelintConfig.js");
var colorFunction = require("postcss-color-function");
var nested = require("postcss-nested");
var sourcemaps = require("gulp-sourcemaps");

// Create the styles
gulp.task("styles", ["lint-styles"], function () {

    var processors = [
        postcssImport({glob: true}),
        mixins,
        simpleVars,
        colorFunction(),
        nested,
        autoprefixer({ browsers: ["last 2 version", "safari 5", "opera 12.1", "ios 6", "android 2.3"] }),
        cssnano
    ];

    return gulp.src("preCSS/styles.css")

    // start Sourcemaps
    .pipe(sourcemaps.init())

    // We always want PostCSS to run
    .pipe(postcss(processors).on( class="st">"error", gutil.log))

    // Write a source map into the CSS at this point
    .pipe(sourcemaps.write())

    // Set the destination for the CSS file
    .pipe(gulp.dest("./build"))

    // If in DEV environment, notify user that styles have been compiled
    .pipe(notify("Yo Mofo, check dem styles!!!"))

    // If in DEV environment, reload the browser
    .pipe(reload({stream: true}));
});

```

对于 Gulp，构建选择是相当无限的，这只是一个示例。但是，请注意 `styles` 任务的第一步是运行 `lint-styles` 任务。

如前几章所述，样式表的 linting 是一个非常重要的步骤，特别是在涉及多个样式表作者的项目中。让我们接下来更深入地了解一下。

### Stylelint

Stylelint 是一个基于 Node 的静态分析样式表的 linting 工具。通俗地说，它会分析你的样式表，找出你特别关心的问题，并警告你任何问题。

### 提示

如果你使用 Sass，你应该查看 *scss-lint*（[`github.com/brigade/scss-lint`](https://github.com/brigade/scss-lint)），它为 Sass 文件提供了类似的功能。

如果发现任何作者错误，linting 任务会导致构建失败。通常情况下，在两个地方运行 linting 是最有益的。在文本编辑器（例如 Sublime）和构建工具（例如 Gulp）中。这样，如果作者有必要的文本编辑器，那么 *基于编辑器的 linting* ([`github.com/kungfusheep/SublimeLinter-contrib-stylelint`](https://github.com/kungfusheep/SublimeLinter-contrib-stylelint)) 就会在作者点击 *保存* 之前指出问题。

即使用户没有编辑器中的 linting 功能，保存时 linting 任务也会通过 Gulp 运行。构建步骤可以防止编译后的代码进入生产环境（因为持续集成软件也会导致构建失败）。

这是一个巨大的时间节省，对于代码的同行审查和质量保证测试来说是非常宝贵的。

这是一个 Stylelint 的 `.stylelintrc` 配置示例（这是针对 Stylelint 的 v5 版本的，所以未来/之前的版本可能会有些许不同）：

```css
{
    "rules": {
        "color-hex-case": "lower",
        "color-hex-length": "long",
        "color-named": "never",
        "color-no-invalid-hex": true,
        "font-family-name-quotes": "always-where-
        required",
        "font-weight-notation": "numeric",
        "function-comma-newline-before": "never-multi-
        line",
        "function-comma-newline-after": "never-multi-
        line",
        "function-comma-space-after": "always",
        "function-comma-space-before": "never",
        "function-linear-gradient-no-nonstandard-
        direction": true,
        "function-max-empty-lines": 0,
        "function-name-case": "lower",
        "function-parentheses-space-inside": "never",
        "function-url-data-uris": "never",
        "function-url-quotes": "always",
        "function-whitespace-after": "always",
        "number-leading-zero": "never",
        "number-no-trailing-zeros": true,
        "string-no-newline": true,
        "string-quotes": "double",
        "length-zero-no-unit": true,
        "unit-case": "lower",
        "unit-no-unknown": true,
        "value-keyword-case": "lower",
        "value-no-vendor-prefix": true,
        "value-list-comma-space-after": "always",
        "value-list-comma-space-before": "never",
        "shorthand-property-no-redundant-values": true,
        "property-case": "lower",
        "property-no-unknown": true,
        "property-no-vendor-prefix": true,
        "declaration-bang-space-before": "always",
        "declaration-bang-space-after": "never",
        "declaration-colon-space-after": "always",
        "declaration-colon-space-before": "never",
        "declaration-empty-line-before": "never",
        "declaration-block-no-duplicate-properties": true,
        "declaration-block-no-ignored-properties": true,
        "declaration-block-no-shorthand-property-
        overrides": true,
        "declaration-block-semicolon-newline-after":
        "always",
        "declaration-block-semicolon-newline-before":
        "never-multi-line",
        "declaration-block-single-line-max-declarations":
        1,
        "declaration-block-trailing-semicolon": "always",
        "block-closing-brace-empty-line-before": "never",
        "block-no-empty": true,
        "block-no-single-line": true,
        "block-opening-brace-newline-after": "always",
        "block-opening-brace-space-before": "always",
        "selector-attribute-brackets-space-inside":
        "never",
        "selector-attribute-operator-space-after":
        "never",
        "selector-attribute-operator-space-before":
        "never",
        "selector-attribute-quotes": "always",
        "selector-class-pattern": "^[a-z{1,3}-[A-Z][a-zA-Z0-9]+(_[A-Z][a-zA-Z0-9]+)?(-([a-z0-9-]+)?[a-z0-9])?$", { "resolveNestedSelectors": true }],
        "selector-combinator-space-after": "always",
        "selector-combinator-space-before": "always",
        "selector-max-compound-selectors": 3,
        "selector-max-specificity": "0,3,0",
        "selector-no-id": true,
        "selector-no-qualifying-type": true,
        "selector-no-type": true,
        "selector-no-universal": true,
        "selector-no-vendor-prefix": true,
        "selector-pseudo-class-case": "lower",
        "selector-pseudo-class-no-unknown": true,
        "selector-pseudo-class-parentheses-space-inside":
        "never",
        "selector-pseudo-element-case": "lower",
        "selector-pseudo-element-colon-notation":
        "single",
        "selector-pseudo-element-no-unknown": true,
        "selector-max-empty-lines": 0,
        "selector-list-comma-newline-after": "always",
        "selector-list-comma-newline-before": "never-
        multi-line",
        "selector-list-comma-space-before": "never",
        "rule-nested-empty-line-before": "never",
        "media-feature-colon-space-after": "always",
        "media-feature-colon-space-before": "never",
        "media-feature-name-case": "lower",
        "media-feature-name-no-vendor-prefix": true,
        "media-feature-no-missing-punctuation": true,
        "media-feature-parentheses-space-inside": "never",
        "media-feature-range-operator-space-after":
        "always",
        "media-feature-range-operator-space-before": "always",
        "at-rule-no-unknown": [true, {"ignoreAtRules": ["mixin"]}],
        "at-rule-no-vendor-prefix": true,
        "at-rule-semicolon-newline-after": "always",
        "at-rule-name-space-after": "always",
        "stylelint-disable-reason": "always-before",
        "comment-no-empty": true,
        "indentation": 4,
        "max-empty-lines": 1,
        "no-duplicate-selectors": true,
        "no-empty-source": true,
        "no-eol-whitespace": true,
        "no-extra-semicolons": true,
        "no-indistinguishable-colors": [true, {
            "threshold": 1,
            "whitelist": [ [ "#333333", "#303030" ] ]
        }],
        "no-invalid-double-slash-comments": true
    }
}
```

这只是一个示例，你可以从 *不断扩展的列表* ([`stylelint.io/user-guide/rules/`](http://stylelint.io/user-guide/rules/)) 中设置你关心的任何规则。如果是第一次使用这类工具，你可能还会发现下载/克隆 *ecss-postcss-shell* ([`github.com/benfrain/ecss-postcss-shell`](https://github.com/benfrain/ecss-postcss-shell)) 也很有用。这是一个基本的 Gulp 设置，用于通过 PostCSS 运行作者样式表，并使用 Stylelint 对样式进行 linting。

### 注意

我甚至为 Stylelint 项目贡献了一点代码，帮助添加了一个名为 `selector-max-specificity` 的规则，用于控制任何选择器的最大特异性级别。如果你参与控制 CSS 代码库，这是一个很好的项目可以参与。

如果这还不够，Stylelint 是可扩展的。很容易添加额外的功能。对于我工作中的当前构建 ECSS 项目，我们有额外的 Stylelint 规则：

+   确保只有覆盖和媒体查询可以嵌套（防止不使用父（`&`）选择器的嵌套）

+   确保关键选择器与 ECSS 命名约定匹配（Stylelint 现在有一个 `selector-class-pattern` 规则来帮助解决这个问题）

+   防止关键选择器成为复合选择器（例如 `.ip-Selector.ip-Selector2 {}`）

+   确保关键选择器是单数（例如 `.ip-Thing` 而不是 `.a-Parent .ip-Thing {}`）

这些提供了定制的质量保证，如果手动执行将会耗费大量时间并容易出错。

如果我没有表达清楚，我想让你知道我喜欢 Stylelint，并认为 linting 是大型 CSS 项目中不可或缺的工具，有多个作者。我简直无法推荐它。

### 注意

关于 Stylelint 还有更多信息，请参阅*这篇博客文章* ([`benfrain.com/floss-your-style-sheets-with-stylelint/`](https://benfrain.com/floss-your-style-sheets-with-stylelint/)) 或者官方的*Stylelint* ([`stylelint.io/`](http://stylelint.io/)) 网站。

# 优化

当 CSS 即将投入生产时，它需要通过*cssnano* ([`cssnano.co/`](http://cssnano.co/)) 进行额外的处理。这是一个由非常有才华的 Ben Briggs 开发的出色且模块化的 CSS 缩小器。强烈推荐。

除了 cssnano 提供的更明显的缩小步骤外，您还可以通过在 PostCSS 生态系统中使用插件执行一些微观优化。例如，通过一致地对 CSS 声明进行排序，Gzip 可以更有效地压缩样式表。这不是我想要手动完成的工作，但*postcss-sorting* ([`github.com/hudochenkov/postcss-sorting`](https://github.com/hudochenkov/postcss-sorting)) 插件可以免费完成。以下是使用各种声明排序配置的 Gzip 文件大小的比较。

举例来说，我拿了一个大型的测试 CSS 文件，未排序时 Gzip 后大小为 37.59 kB。这是同一个文件在使用其他声明排序配置后 Gzip 后的文件大小：

+   postcss-sorting: 37.54

+   CSSComb: 37.46

+   Yandex: 37.48

+   Zen: 37.41

所以，我们最多只能节省原始大小的不到 1%。虽然是微小的节约，但你可以免费有效地获得它。

还有其他一些类似的优化，比如将类似的媒体查询分组，但我会留下这些微观优化供您探索，如果您对它们感兴趣的话。

# 总结

在本章中，我们已经介绍了工具，以促进不断的代码质量和改进的样式表编写体验。然而，您应该知道，我们所涵盖的所有内容中，这里列出的具体工具可能是最短命的。工具技术发展迅速。仅仅三年时间，我从普通的 CSS，转到了 Sass（带有*scss-lint*（[`github.com/brigade/scss-lint`](https://github.com/brigade/scss-lint)）），再到了 PostCSS 和 Stylelint，同时也从 CodeKit 这样的 GUI 构建工具转到了 JavaScript 构建工具 Grunt，然后是 Gulp，现在是 NPM 脚本。

我不知道在 6 个月后最好的选择是什么，所以要记住的是要考虑工具和方法如何改进团队的样式表编写体验，而不是当前的工具是什么。

|   | *在你的个人关系中要忠诚，但在你选择的工具和技术上要多变* |   |
| --- | --- | --- |
|   | --*务实编码之道 ([`benfrain.com/be-better-front-end-developer-way-of-pragmatic-coding/`](https://benfrain.com/be-better-front-end-developer-way-of-pragmatic-coding/))* |

# 结束的右花括号

现在，朋友们，我们已经到达了这本小书的结尾。

虽然我希望你们中的一些人能够接受 ECSS 并开始全面实施它，但如果它只是激发了你自己的探索之旅，我同样会很高兴。

一开始，我试图找到一种处理以下问题的 CSS 扩展方法：

+   允许随着时间的推移轻松维护大型的 CSS 代码库

+   允许从代码库中删除 CSS 代码的部分，而不影响其余的样式

+   应该能够快速迭代任何新设计

+   更改应用于一个视觉元素的属性和值不应无意中影响其他元素

+   任何解决方案都应该需要最少的工具和工作流程更改来实施

+   在可能的情况下，应使用 W3C 标准，如 ARIA，来传达用户界面中的状态变化

ECSS 解决了所有这些问题：

+   将 CSS 分隔成模块可以轻松删除已弃用的功能

+   独特的命名约定避免了全局命名冲突，降低了特异性，并防止了对不相关元素的不必要更改

+   由于所有新模块都是*greenfield*，因此可以轻松构建新设计

+   尽管有一些工具可以适应全局导入和 linting，我们仍然在 CSS 文件中编写 CSS，这使得开发人员的入职过程变得更加容易

+   我们也可以接受 ARIA 作为控制和传达状态变化的手段，不仅仅是为了辅助技术，而且在更广泛的意义上也是如此

考虑到 CSS 的扩展是一种有点小众的追求。在未来，我们将拥有诸如*CSS Scoping* ([`www.w3.org/TR/css-scoping-1/#scope-atrule`](http://www.w3.org/TR/css-scoping-1/#scope-atrule))之类的东西，但在那之前，我们必须利用手头的工具和技术来弯曲现有技术以符合我们的意愿。

我已经多次提到过，有很多方法可以解决这个问题。其他方法可能更可取。以下是一些人和资源的列表，没有特定顺序，可能有助于你自己的探索。

亲爱的读者，直到下次，祝你探险愉快。

|   | *吸收有用的东西，拒绝无用的东西，添加特别属于你自己的东西。* |   |
| --- | --- | --- |
|   | --*李小龙* |

## 资源

以下是一些经常谈论或写作关于 CSS 架构/扩展的人：

+   Thierry Koblentz：[`cssmojo.com/`](http://cssmojo.com/)

+   Nicolas Gallagher：[`nicolasgallagher.com/`](http://nicolasgallagher.com/)

+   Kaelig Deloumeau-Prigent：[`kaelig.fr/`](http://kaelig.fr/)

+   Nicole Sullivan：[`www.stubbornella.org/content/`](http://www.stubbornella.org/content/)

+   哈里·罗伯茨：[`csswizardry.com/`](http://csswizardry.com/)

+   乔纳森·斯努克：[`snook.ca/`](https://snook.ca/)

+   Micah Godbolt：[`www.godbolt.me/`](http://www.godbolt.me/)

关于使用 JavaScript 内联样式的讨论：*Shop Talk show #180* ([`shoptalkshow.com/episodes/180-panel-on-inline-styles/`](http://shoptalkshow.com/episodes/180-panel-on-inline-styles/))

围绕 CSS 的有趣方法/项目：

+   React 的 Radium：[`github.com/FormidableLabs/radium`](https://github.com/FormidableLabs/radium)

+   React Native for Web：[`github.com/necolas/react-native-web`](https://github.com/necolas/react-native-web)

+   CSS 模块：[`github.com/css-modules`](https://github.com/css-modules)

+   原子 CSS：[`acss.io/`](http://acss.io/)


# 附录 1. CSS 选择器性能

2014 年初，我与一些其他开发人员进行了一场*辩论*（我在那里用了引号），讨论了担心 CSS 选择器速度的相关性或无关性。

每当交换关于 CSS 选择器相对速度的理论/证据时，开发人员经常引用*Steve Souders*（[`stevesouders.com/`](http://stevesouders.com/)）2009 年关于 CSS 选择器的工作。它被用来验证诸如*属性选择器速度慢*或*伪选择器速度慢*等说法。

在过去的几年里，我觉得这些事情根本不值得担心。多年来我一直在重复的一句话是：

> *对于 CSS，架构在大括号外；性能在大括号内*

但是，除了参考*Nicole Sullivan 在 Performance Calendar 上的后续帖子*（[`calendar.perfplanet.com/2011/css-selector-performance-has-changed-for-the-better/`](http://calendar.perfplanet.com/2011/css-selector-performance-has-changed-for-the-better/)）来支持我对所使用的选择器并不重要的信念外，我从未真正测试过这个理论。

为了解决这个问题，我尝试自己进行一些测试，以解决这个争论。至少，我相信这会促使更有知识/证据的人提供进一步的数据。

# 测试选择器速度

Steve Souders 之前的测试使用了 JavaScript 的`new Date()`。然而，现在，现代浏览器（iOS/Safari 在测试时是一个明显的例外）支持*导航定时 API*（[`www.w3.org/TR/navigation-timing/`](https://www.w3.org/TR/navigation-timing/)），这为我们提供了更准确的测量。对于测试，我实现了这样的方法：

```css
<script>
    ;(function TimeThisMother() {
        window.onload = function(){
            setTimeout(function(){
            var t = performance.timing;
                alert("Speed of selection is: " + (t.loadEventEnd - t.responseEnd) + " milliseconds");
            }, 0);
        };
    })();
</script>
```

这让我们可以将测试的时间限制在所有资产都已接收（`responseEnd`）和页面呈现（`loadEventEnd`）之间。

因此，我设置了一个非常简单的测试。20 个不同的页面，所有页面都有相同的巨大 DOM，由 1000 个相同的标记块组成：

```css
<div class="tagDiv wrap1">
  <div class="tagDiv layer1" data-div="layer1">
    <div class="tagDiv layer2">
      <ul class="tagUl">
        <li class="tagLi"><b class="tagB"><a href="/" class="tagA link" data-select="link">Select</a></b></li>
      </ul>
    </div>
  </div>
</div>
```

测试了 20 种不同的 CSS 选择方法来将最内部的节点着色为红色。每个页面只在应用于选择块内最内部节点的规则上有所不同。以下是测试的不同选择器和该选择器的测试页面链接：

1.  数据属性：[`benfrain.com/selector-test/01.html`](https://benfrain.com/selector-test/01.html)

1.  数据属性（带修饰）：[`benfrain.com/selector-test/02.html`](https://benfrain.com/selector-test/02.html)

1.  数据属性（未经修饰但有值）：[`benfrain.com/selector-test/03.html`](https://benfrain.com/selector-test/03.html)

1.  数据属性（带值）：[`benfrain.com/selector-test/04.html`](https://benfrain.com/selector-test/04.html)

1.  多个数据属性（带值）：[`benfrain.com/selector-test/05.html`](https://benfrain.com/selector-test/05.html)

1.  单独伪选择器（例如`:after`）：[`benfrain.com/selector-test/06.html`](https://benfrain.com/selector-test/06.html)

1.  组合类（例如`class1.class2`）：[`benfrain.com/selector-test/07.html`](https://benfrain.com/selector-test/07.html)

1.  多个类：[`benfrain.com/selector-test/08.html`](https://benfrain.com/selector-test/08.html)

1.  多个类与子选择器：[`benfrain.com/selector-test/09.html`](https://benfrain.com/selector-test/09.html)

1.  部分属性匹配（例如`[class<sup>ˆ=</sup>“wrap”]`）：[`benfrain.com/selector-test/10.html`](https://benfrain.com/selector-test/10.html)

1.  nth-child 选择器：[`benfrain.com/selector-test/11.html`](https://benfrain.com/selector-test/11.html)

1.  紧接着另一个 nth-child 选择器的 nth-child 选择器：[`benfrain.com/selector-test/12.html`](https://benfrain.com/selector-test/12.html)

1.  疯狂选择（所有选择都有资格，每个类都使用，例如`div.wrapper``> div.tagDiv > div.tagDiv.layer2 > ul.tagUL > li.tagLi > b.tagB > a.TagA.link`）：[`benfrain.com/selector-test/13.html`](https://benfrain.com/selector-test/13.html)

1.  轻微疯狂选择（例如`.tagLi .tagB a.TagA.link`）：[`benfrain.com/selector-test/14.html`](https://benfrain.com/selector-test/14.html)

1.  通用选择器：[`benfrain.com/selector-test/15.html`](https://benfrain.com/selector-test/15.html)

1.  单一元素：[`benfrain.com/selector-test/16.html`](https://benfrain.com/selector-test/16.html)

1.  元素双：[`benfrain.com/selector-test/17.html`](https://benfrain.com/selector-test/17.html)

1.  元素三倍：[`benfrain.com/selector-test/18.html`](https://benfrain.com/selector-test/18.html)

1.  元素三倍带伪：[`benfrain.com/selector-test/19.html`](https://benfrain.com/selector-test/19.html)

1.  单一类：[`benfrain.com/selector-test/20.html`](https://benfrain.com/selector-test/20.html)

每个浏览器上的测试运行了 5 次，并且结果是在 5 个结果之间平均的。测试的浏览器：

+   Chrome 34.0.1838.2 dev

+   Firefox 29.0a2 Aurora

+   Opera 19.0.1326.63

+   Internet Explorer 9.0.8112.16421

+   Android 4.2（7 英寸平板电脑）

使用了 Internet Explorer 的以前版本（而不是我可以使用的最新 Internet Explorer）来揭示*非常绿色*浏览器的表现。所有其他测试过的浏览器都定期更新，所以我想确保现代定期更新的浏览器处理 CSS 选择器的方式与稍旧的浏览器有没有明显的差异。

### 注意

想要自己尝试相同的测试吗？去这个 GitHub 链接获取文件：[`github.com/benfrain/css-performance-tests`](https://github.com/benfrain/css-performance-tests)。只需在您选择的浏览器中打开每个页面（记住浏览器必须支持网络定时 API 以警报响应）。还要注意，当我进行测试时，我丢弃了前几个结果，因为它们在某些浏览器中往往异常高。

### 提示

在考虑结果时，不要将一个浏览器与另一个浏览器进行比较。这不是测试的目的。目的纯粹是为了尝试和评估每个浏览器上使用的不同选择器的选择速度之间的比较差异。例如，选择器 3 是否比任何浏览器上的选择器 7 更快？因此，当查看表格时，最好看列而不是行。

以下是结果。所有时间以毫秒为单位：

| **测试** | **Chrome 34** | **Firefox 29** | **Opera 19** | **IE 19** | **Android 4** |
| --- | --- | --- | --- | --- | --- |
| 1 | 56.8 | 125.4 | 63.6 | 152.6 | 1455.2 |
| 2 | 55.4 | 128.4 | 61.4 | 141 | 1404.6 |
| 3 | 55 | 125.6 | 61.8 | 152.4 | 1363.4 |
| 4 | 54.8 | 129 | 63.2 | 147.4 | 1421.2 |
| 5 | 55.4 | 124.4 | 63.2 | 147.4 | 1411.2 |
| 6 | 60.6 | 138 | 58.4 | 162 | 1500.4 |
| 7 | 51.2 | 126.6 | 56.8 | 147.8 | 1453.8 |
| 8 | 48.8 | 127.4 | 56.2 | 150.2 | 1398.8 |
| 9 | 48.8 | 127.4 | 55.8 | 154.6 | 1348.4 |
| 10 | 52.2 | 129.4 | 58 | 172 | 1420.2 |
| 11 | 49 | 127.4 | 56.6 | 148.4 | 1352 |
| 12 | 50.6 | 127.2 | 58.4 | 146.2 | 1377.6 |
| 13 | 64.6 | 129.2 | 72.4 | 152.8 | 1461.2 |
| 14 | 50.2 | 129.8 | 54.8 | 154.6 | 1381.2 |
| 15 | 50 | 126.2 | 56.8 | 154.8 | 1351.6 |
| 16 | 49.2 | 127.6 | 56 | 149.2 | 1379.2 |
| 17 | 50.4 | 132.4 | 55 | 157.6 | 1386 |
| 18 | 49.2 | 128.8 | 58.6 | 154.2 | 1380.6 |
| 19 | 48.6 | 132.4 | 54.8 | 148.4 | 1349.6 |
| 20 | 50.4 | 128 | 55 | 149.8 | 1393.8 |
| 最大差异 | 16 | 13.6 | 17.6 | 31 | 152 |
| 最低 | 13 | 6 | 13 | 10 | 6 |

## 最快选择器和最慢选择器之间的差异

**最大差异**行显示了最快和最慢选择器之间的毫秒差异。在桌面浏览器中，IE9 以**31**毫秒的最大差异脱颖而出。其他浏览器的差异都在这个数字的一半左右。然而，有趣的是。

## 最慢的选择器

我注意到，最慢的选择器类型在不同的浏览器中有所不同。Opera 和 Chrome 都发现*insanity*选择器（测试 13）最难匹配（这里 Opera 和 Chrome 的相似性可能并不令人惊讶，因为它们共享*blink*引擎），而 Firefox 和 Android 4.2 设备（Tesco hudl 7 英寸平板电脑）都难以匹配单个伪选择器（*测试 6*），Internet Explorer 9 的软肋是部分属性选择器（*测试 10*）。

# 良好的 CSS 架构实践

我们可以肯定的是，使用基于类的选择器的扁平层次结构，就像 ECSS 一样，提供的选择器与其他选择器一样快。 

## 这意味着什么？

对我来说，这证实了我的信念，即担心所使用的选择器类型是绝对愚蠢的。对选择器引擎进行猜测是毫无意义的，因为选择器引擎处理选择器的方式显然是不同的。而且，即使在像这样的庞大 DOM 上，最快和最慢的选择器之间的差异也不是很大。正如我们在英格兰北部所说，“有更重要的事情要做”。

自从记录了我的原始结果以来，WebKit 工程师本杰明·普兰联系我，指出了他对所使用方法的担忧。他的评论非常有趣，他提到的一些信息如下所述：

> *通过选择通过加载来衡量性能，你正在衡量比 CSS 大得多的东西，CSS 性能只是加载页面的一小部分。*

如果以`[class^="wrap"]`的时间配置文件为例（在旧的 WebKit 上进行，以便与 Chrome 有些相似），我看到：

+   ~10%的时间用于光栅化。

+   ~21%的时间用于第一次布局。

+   ~48%的时间用于解析器和 DOM 树的创建

+   ~8%用于样式解析

+   ~5%用于收集样式-这是我们应该测试的内容，也是最耗时的内容。（剩下的时间分布在许多小函数中）。

通过上面的测试，我们可以说我们有一个基线为 100 毫秒的最快选择器。其中，5 毫秒将用于收集样式。如果第二个选择器慢 3 倍，总共将显示为 110 毫秒。测试应该报告 300%的差异，但实际上只显示了 10%。

在这一点上，我回答说，虽然我理解本杰明指出的问题，但我的测试只是为了说明，相同的页面，在其他所有条件相同的情况下，无论使用哪种选择器，渲染基本上都是相同的。本杰明花时间回复并提供了更多细节：

> *我完全同意提前优化选择器是没有用的，但原因完全不同：*
> 
> *仅仅通过检查选择器就几乎不可能预测给定选择器的最终性能影响。在引擎中，选择器被重新排序、拆分、收集和编译。要知道给定选择器的最终性能，你必须知道选择器被收集到了哪个桶中，它是如何编译的，最后 DOM 树是什么样子的。*
> 
> *各种引擎之间都非常不同，使整个过程变得更不可预测。*
> 
> *我反对网页开发人员优化选择器的第二个论点是，他们可能会让情况变得更糟。关于选择器的错误信息比正确的跨浏览器信息要多。有人做正确的事情的机会是相当低的。*
> 
> 在实践中，人们发现 CSS 的性能问题，并开始逐条删除规则，直到问题消失。我认为这是正确的做法，这样做很容易，并且会导致正确的结果。

## 因果关系

在这一点上，我感到 CSS 选择器的使用几乎是无关紧要的。然而，我想知道我们还能从测试中得出什么。

如果页面上的 DOM 元素数量减半，正如你所期望的，完成任何测试的速度也相应下降。但在现实世界中，减少 DOM 的大部分并不总是可能的。这让我想知道 CSS 中未使用的样式数量对结果的影响。

# 样式膨胀会产生什么影响？

*另一个测试*（[`benfrain.com/selector-test/2-01.html`](https://benfrain.com/selector-test/2-01.html)）：我拿了一张与 DOM 树完全无关的庞大样式表。大约有 3000 行 CSS。所有这些无关的样式都是在最后一个选择我们内部的`a.link`节点并将其变红的规则之前插入的。我对每个浏览器进行了 5 次运行的结果平均值。

*然后删除了一半的规则并重复了测试*（[`benfrain.com/selector-test/2-02.html`](https://benfrain.com/selector-test/2-02.html)）以进行比较。以下是结果：

| **测试** | **Chrome 34** | **Firefox 29** | **Opera 19** | **IE 19** | **Android 4** |
| --- | --- | --- | --- | --- | --- |
| 完全膨胀 | 64.4 | 237.6 | 74.2 | 436.8 | 1714.6 |
| 一半膨胀 | 51.6 | 142.8 | 65.4 | 358.6 | 1412.4 |

## 规则减肥

这提供了一些有趣的数据。例如，Firefox 在完成这个测试时比其最慢的选择器测试（测试 6）慢了 1.7 倍。Android 4.3 比其最慢的选择器测试（测试 6）慢了 1.2 倍。Internet Explorer 比其最慢的选择器慢了 2.5 倍！

你可以看到，当删除了一半的样式（大约 1500 行）后，Firefox 的速度大大下降。Android 设备在那时也降到了其最慢选择器的速度。

## 删除未使用的样式

这种恐怖的场景对你来说是不是很熟悉？巨大的 CSS 文件包含各种选择器（通常包含甚至不起作用的选择器），大量更具体的选择器，七层或更深的选择器，不适用的供应商前缀，到处都是 ID 选择器，文件大小为 50-80 KB（有时更大）。

如果你正在处理一个有着庞大 CSS 文件的代码库，而且没有人确切知道所有这些样式实际上是用来做什么的，我的建议是在选择器之前查看 CSS 优化。希望到这一点你会相信 ECSS 方法在这方面可能会有所帮助。

但这并不一定会帮助 CSS 的实际性能。

# 括号内的性能

*最终测试*（[`benfrain.com/selector-test/3-01.html`](https://benfrain.com/selector-test/3-01.html)）我进行的是对页面应用一堆*昂贵*的属性和值。考虑这条规则：

```css

.link {
    background-color: red;
    border-radius: 5px;
    padding: 3px;
    box-shadow: 0 5px 5px #000;
    -webkit-transform: rotate(10deg);
    -moz-transform: rotate(10deg);
    -ms-transform: rotate(10deg);
    transform: rotate(10deg);
    display: block;
}

```

应用了这条规则后，以下是结果：

| **测试** | **Chrome 34** | **Firefox 29** | **Opera 19** | **IE 19** | **Android 4** |
| --- | --- | --- | --- | --- | --- |
| 昂贵的样式 | 65.2 | 151.4 | 65.2 | 259.2 | 1923 |

在这里，所有浏览器至少都达到了其最慢选择器的速度（IE 比其最慢的选择器测试（10）慢了 1.5 倍，Android 设备比最慢的选择器测试（测试 6）慢了 1.3 倍），但这还不是全部。试着滚动那个页面！这种样式的重绘可能会让浏览器崩溃（或者浏览器的等价物）。

我们放在大括号内的属性才是真正影响性能的。可以想象，滚动一个需要无休止昂贵的重绘和布局更改的页面会给设备带来压力。高分辨率屏幕？这会更糟，因为 CPU/GPU 会努力在 16 毫秒内将所有内容重新绘制到屏幕上。

在昂贵的样式测试中，在我测试的 15 英寸 Retina MacBook Pro 上，Chrome 连续绘制模式中显示的绘制时间从未低于 280 毫秒（请记住，我们的目标是低于 16 毫秒）。为了让你有所了解，第一个选择器测试页面从未超过 2.5 毫秒。这不是打错字。这些属性导致绘制时间增加了 112 倍。天啊，这些属性真是昂贵啊！确实是罗宾。确实是。

## 什么属性是昂贵的？

*昂贵*的属性/值配对是我们可以相当确信会使浏览器在重新绘制屏幕时感到吃力的（例如在滚动时）。

我们如何知道什么样式是*昂贵*的？幸运的是，我们可以运用常识来得出一个相当好的想法，知道什么会让浏览器负担。任何需要浏览器在绘制到页面之前进行操作/计算的东西都会更加昂贵。例如，盒阴影，边框半径，透明度（因为浏览器必须计算下面显示的内容），变换和性能杀手，如 CSS 滤镜-如果性能是你的优先考虑因素，那么任何类似的东西都是你的大敌。

### 注意

Juriy kangax Zaytsev 在 2012 年做了一篇`非常棒的博客文章，也涵盖了 CSS 性能`（[`perfectionkills.com/profiling-css-for-fun-and-profit-optimization-notes/`](http://perfectionkills.com/profiling-css-for-fun-and-profit-optimization-notes/)）。他使用各种开发者工具来衡量性能。他特别出色地展示了各种属性对性能的影响。如果你对这种事情感兴趣，那么这篇文章绝对值得一读。

# 总结

从这些测试中得出的一些要点：

+   在现代浏览器中纠结于所使用的选择器是徒劳的；大多数选择方法现在都非常快，真的不值得花太多时间在上面。此外，不同浏览器对最慢的选择器也存在差异。最后查看这里以加快你的 CSS 速度。

+   过多的未使用样式可能会在性能上造成更多的损失，而不是你选择的任何选择器，所以第二要整理那里。在页面上有 3000 行未使用或多余的样式并不罕见。虽然将所有样式都捆绑到一个大的`styles.css`中很常见，但如果站点/网络应用的不同区域可以添加不同的（额外的）样式表（依赖图样式），那可能是更好的选择。

+   如果你的 CSS 随着时间被多位不同的作者添加，可以使用*UnCSS*等工具（[`github.com/giakki/uncss`](https://github.com/giakki/uncss)）来自动删除样式；手动进行这个过程并不有趣！

+   高性能 CSS 的竞争不在于所使用的选择器，而在于对属性和值的慎重使用。

+   快速将某物绘制到屏幕上显然很重要，但用户与页面交互时页面的感觉也很重要。首先寻找昂贵的属性和值对（Chrome 连续重绘模式在这里是你的朋友），它们可能会带来最大的收益。


# 附录 2. 浏览器代表对 CSS 性能的看法

作为附录 1 的补充，*CSS 选择器性能*，以下文字涉及浏览器代表对 CSS 性能的看法。

# TL;DR

如果你不想读这一节的其他内容，那么请读下一段并牢记：

在没有检查自己的*数据*之前，不要记忆与 CSS 性能相关的规则。它们基本上是无用的、短暂的和太主观的。相反，熟悉工具并使用它们来揭示自己场景的相关数据。这基本上是 Chrome 开发者关系人员多年来一直在推广的口号，我相信是 Paul Lewis（下文还有更多）创造了与 Web 性能故障排除相关的术语*工具，而不是规则*。

现在我理解那种情绪。真的理解了。

# 浏览器代表对 CSS 性能的看法

通常情况下，我在编写样式表时不太担心 CSS 选择器（通常我只是在我想要设置样式的任何东西上放一个类并直接选择它），但偶尔我会看到一些比我聪明得多的人对特定的选择器发表评论。以下是*Paul Irish*（[`www.paulirish.com/`](https://www.paulirish.com/)）在与*Heydon Pickering*（[`alistapart.com/article/quantity-queries-for-css`](http://alistapart.com/article/quantity-queries-for-css)）的一篇文章相关的评论，该文章使用了一种特定类型的选择器：

> *这些选择器是可能的最慢的。比像 div.box:not(:empty):last-of-type .title”这样的东西慢大约 500 倍。测试页面 http://jsbin.com/gozula/1/quiet。也就是说，选择器速度很少是一个问题，但如果这个选择器最终出现在一个 DOM 变化非常频繁的动态 Web 应用程序中，它可能会产生很大的影响。因此，对于许多用例来说是不错的，但请记住，随着应用程序的成熟，它可能成为性能瓶颈。这是一个需要在那时进行分析的事情。干杯*

我们应该从中得出什么？我们是否应该在头脑中将这种选择器放在某种*紧急情况下不要使用*的保险库中？

为了得到一些*真正*的答案，我询问了实际在浏览器上工作的聪明人，问他们对 CSS 性能应该关注什么。

在前端世界中，我们很幸运，因为 Chrome 开发者关系团队是如此可及。然而，我喜欢平衡。此外，我还联系了微软和火狐的人，并包括了 WebKit 的一些很好的意见。

# 我们应该担心 CSS 选择器吗？

问题本质上是，*作者是否应该关注与 CSS 性能相关的选择器？*

让我们从开始的地方开始，那里有 CSSOM 和 DOM 实际上被构建。Chrome 开发者关系的开发者倡导者*Paul Lewis*（[`aerotwist.com/`](http://aerotwist.com/)）解释说，*样式计算受两个因素影响：选择器匹配和无效大小。当你首次加载页面时，所有元素的所有样式都需要计算，这取决于树的大小和选择器的数量。*

更详细的内容，Lewis 引用了 Opera 团队的*Rune Lillesveen*（[`docs.google.com/document/d/1vEW86DaeVs4uQzNFI5R-_xS9TcS1Cs_EUsHRSgCHGu8/edit#`](https://docs.google.com/document/d/1vEW86DaeVs4uQzNFI5R-_xS9TcS1Cs_EUsHRSgCHGu8/edit#)）的话：

> *在撰写本文时，大约 50%的时间用于计算元素的计算样式，用于匹配选择器，另一半时间用于从匹配规则构造 RenderStyle（计算样式表示）*

好吧，这对我来说有点*科学*，那是否意味着我们需要担心选择器呢？

Lewis 再次说道，*选择器匹配可能会影响性能，但树的大小往往是最重要的因素*。

这是理所当然的，如果你有一个庞大的 DOM 树和一大堆无关的样式，事情就会开始变得困难。我的自己的*膨胀测试*（[`benfrain.com/selector-test/2-01.html`](https://benfrain.com/selector-test/2-01.html)）支持这一点。再考虑另一种情况。如果我给你两堆各有 1000 张卡片，除了 5 张匹配的卡片外，每堆上的卡片名字都不同，那么很显然要花更长的时间来配对这些匹配的名字，而不是只有 100 张或 10 张卡片。对于浏览器也是同样的道理。

我认为我们都可以同意，样式膨胀比使用的 CSS 选择器更令人担忧。也许这是我们可以信赖的一个规则？

|   | *对于大多数网站，我认为选择器性能不是值得花时间寻找性能优化的最佳领域。我强烈建议专注于括号内的内容，而不是括号外的选择器* |   |
| --- | --- | --- |
|   | --*Greg Whitworth, 微软的项目经理* |

# 那么 JavaScript 呢

然而，Whitworth 也指出，在处理 JavaScript 和 DOM 结构的动态性时需要额外的注意，*如果你一遍又一遍地使用 JavaScript 在事件上添加或替换类，你应该考虑这将如何影响整体的网络管道和你正在操作的盒子的 DOM 结构*。

这与*Paul Irish*（[`www.paulirish.com/`](https://www.paulirish.com/)）早期的评论相吻合。由于类的更改而导致 DOM 区域的快速失效有时可能会显示出复杂的选择器。那么，也许我们应该担心选择器？

|   | *每个规则都有例外，有些选择器比其他选择器更有效，但我们通常只在有大量 DOM 树和 JavaScript 反模式导致 DOM 抖动和额外布局或绘制发生的情况下才会看到这些选择器* |   |
| --- | --- | --- |
|   | --Whitworth |

对于更简单的 JavaScript 更改，Lewis 提供了这样的建议，*解决方案通常是尽可能地紧密地定位元素，尽管 Blink 越来越聪明，可以确定哪些元素真正会受到对父元素的更改的影响*。因此，实际上，如果可能的话，如果你需要影响 DOM 元素的更改，最好是在 DOM 树中直接在它上面添加一个类，而不是在 body 或 html 节点上。

# 处理 CSS 性能

在这一点上，我很高兴地得出了在附录 1 中得出的结论，*CSS 选择器性能* - CSS 选择器在静态页面中很少会出现问题。此外，试图预测哪个选择器会表现良好可能是徒劳的。

然而，对于大型 DOM 和动态 DOM（例如不仅仅是偶尔的类切换，我们说的是大量的 JavaScript 操作），CSS 选择器可能会成为一个问题并不是不可能的。*我不能代表所有的 Mozilla，但我认为当你处理性能问题时，你需要关注什么是慢的。有时候会是选择器；通常会是其他事情*，来自*Mozilla*（[`www.mozilla.org/en-US/`](https://www.mozilla.org/en-US/)）和 W3C 的 CSS 工作组成员*L. David Baron*（[`dbaron.org/`](http://dbaron.org/)）说道。*我确实看到过选择器性能很重要的页面，也确实看到过很多页面选择器性能并不重要*。

那么我们应该怎么做？什么是最实用的方法？

|   | *你应该使用性能分析工具来确定你的性能问题在哪里，然后努力解决这些问题* |   |
| --- | --- | --- |
|   | --*Baron* |

我和所有人交谈的时候都表达了这些观点。

# 总结

如果您在网络上开发了一段时间，就会知道大多数与网络相关的问题的答案是“这取决于情况”。我讨厌在 CSS 性能方面没有简单的、铁一般的规则可以在任何情况下依赖。我真的很想在这里写出那些规则，并相信它们是普遍适用的。但我不能，因为在性能方面根本没有普遍适用的“铁一般”的真理。永远不可能有，因为变量太多了。引擎更新，布局方法变得更加优化，每个 DOM 树都不同，所有的 CSS 文件也都不同。如此循环往复。你明白了吧。

我害怕我能提供的最好建议就是不要提前担心 CSS 选择器或布局方法。它们不太可能是你的问题（但是，你知道，它们可能会是）。相反，集中精力去做“那件事”。然后，当“那件事”做好了，测试“那件事”。如果它慢或者出了问题，找到问题并修复“那件事”。

## 额外信息

+   Greg Whitworth 推荐*2012 年 Build talk*（[`blogs.msdn.com/b/ie/archive/2012/11/20/build-2012-50-performance-tricks-to-make-your-html5-applications-and-sites-faster.aspx`](http://blogs.msdn.com/b/ie/archive/2012/11/20/build-2012-50-performance-tricks-to-make-your-html5-applications-and-sites-faster.aspx)）

+   *CSS Triggers*（[`csstriggers.com/`](https://csstriggers.com/)）由 Paul Lewis 指出了 CSS 中的哪些变化会触发 Blink 引擎（Chrome/Opera）中的布局、绘制和合成操作。
