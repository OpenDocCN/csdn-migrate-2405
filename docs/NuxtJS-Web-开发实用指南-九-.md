# NuxtJS Web 开发实用指南（九）

> 原文：[`zh.annas-archive.org/md5/95454EEF6B1A13DFE0FAD028BE716A19`](https://zh.annas-archive.org/md5/95454EEF6B1A13DFE0FAD028BE716A19)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

使用 CMS 和 GraphQL 创建 Nuxt 应用

在前几章中，您一直在从头开始创建 API，以便它们与 Nuxt 应用一起工作。构建个性化的 API 可能是有益的和令人满足的，但它可能并不适合每种情况。从底层构建 API 是耗时的。在本章中，我们将探索可以为我们提供所需 API 服务的第三方系统，而无需从头开始构建它们。理想情况下，我们希望使用一个可以帮助我们管理内容的系统 - **内容管理系统**（**CMS**）。

WordPress 和 Drupal 是流行的 CMS。它们都包含值得研究的 API。在本书中，我们将使用**WordPress**。除了 WordPress 这样的 CMS，我们还将研究**无头 CMS**。无头 CMS 就像 WordPress 一样，但是是一个纯粹的 API 服务，没有前端呈现，这可以在 Nuxt 中完成，就像我们在整本书中一直在做的那样。**Keystone**将是我们在本书中探索的无头 CMS。然而，WordPress API 和 Keystone API 是两种不同类型的 API。具体来说，前者是**REST API**，而后者是**GraphQL API**。但它们是什么？简而言之，REST API 是使用 HTTP 请求来`GET`、`PUT`、`POST`和`DELETE`数据的 API。您在前几章中创建的 API 都是 REST API。GraphQL 是实现 GraphQL 规范（技术标准）的 API。

GraphQL API 是 REST API 的一种替代方案。为了演示如何使用这两种不同类型的 API 来实现相同的结果，我们将使用我们在第四章中提供的示例 Nuxt 应用网站，*添加视图、路由和过渡*。这可以在本书的 GitHub 存储库中的`/chapter-4/nuxt-universal/sample-website/`中找到。我们将重构现有页面（主页、关于、项目、内容和项目子页面），这些页面包括文本和图片（特色图片、全屏图片和单独的项目图片）。我们还将通过从 API 获取数据而不是硬编码来重构导航，就像我们在前几章中为其他 Nuxt 应用所做的那样。通过 CMS，我们可以通过 API 动态获取导航数据，无论是 REST 还是 GraphQL API。

此外，我们将使用这些 CMS 生成静态 Nuxt 页面（您在第十四章中了解了这些内容，*使用 Linter、格式化程序和部署命令*，以及第十五章中，*使用 Nuxt 创建 SPA*）。因此，到本章结束时，您将对本书中学到的内容有一个完整而最终的了解。

在本章中，我们将涵盖以下主题：

+   在 WordPress 中创建无头 REST API

+   介绍 Keystone

+   介绍 GraphQL

+   集成 Keystone、GraphQL 和 Nuxt

让我们开始研究 WordPress REST API。

# 第十八章：在 WordPress 中创建无头 REST API

WordPress（WordPress.org）是一个用于通用网站开发的开源 PHP CMS。它默认情况下不是“无头”的；它堆叠了一个模板系统。这意味着视图和数据是交织在一起的。然而，自 2015 年以来（WordPress 4.4），REST API 基础设施已经集成到 WordPress 核心中供开发人员使用，现在如果您在基于网站的 URL 后附加`/wp-json/`，则可以访问所有默认端点。您还可以扩展 WordPress REST API 并添加自己的自定义端点。因此，我们可以通过忽略视图轻松地将 WordPress 用作“无头”REST API。您将在接下来的章节中了解如何实现这一点。为了加快开发过程，我们将安装以下 WordPress 插件：

+   **高级自定义字段（ACF）**用于创建自定义元框。有关此插件的更多信息，请访问[`www.advancedcustomfields.com/`](https://www.advancedcustomfields.com/)

+   **ACF Repeater Field**用于创建可重复的子字段集。这是一个 ACF 高级附加组件（[`www.advancedcustomfields.com/add-ons/`](https://www.advancedcustomfields.com/add-ons/)）。您可以从[`www.advancedcustomfields.com/add-ons/repeater-field/`](https://www.advancedcustomfields.com/add-ons/repeater-field/)购买它。或者，您可以从 ACF PRO 的[`www.advancedcustomfields.com/pro/`](https://www.advancedcustomfields.com/pro/)默认获取它。

+   **重写规则检查器**用于检查和刷新 WordPress 中的重写规则。有关此插件的更多信息，请访问[`wordpress.org/plugins/rewrite-rules-inspector/`](https://wordpress.org/plugins/rewrite-rules-inspector/)

如果您不想使用任何这些，您可以创建自己的插件和元框。请查看如何在[`developer.wordpress.org/plugins/metadata/custom-meta-boxes/`](https://developer.wordpress.org/plugins/metadata/custom-meta-boxes/)创建自定义元框。还可以查看如何在[`developer.wordpress.org/plugins/intro/`](https://developer.wordpress.org/plugins/intro/)开发自定义插件。

有关 WordPress REST API 的更多信息，请访问[`developer.wordpress.org/rest-api/`](https://developer.wordpress.org/rest-api/)。

要使用这些插件或您自己的插件开发和扩展 WordPress REST API，首先需要下载 WordPress 并在您的计算机上安装该程序。我们将在下一节中学习如何做到这一点。

## 安装 WordPress 并创建我们的第一个页面

我们可以通过几种方式安装和提供 WordPress：

+   通过解压下载的 WordPress `.zip`文件并从目录中安装它

+   使用 WordPress CLI（[`make.wordpress.org/cli/handbook/`](https://make.wordpress.org/cli/handbook/)或[`wp-cli.org/`](https://wp-cli.org/)）

+   通过使用 Apache 设置端口（可能有点麻烦）

+   通过使用内置的 PHP 服务器

在本书中，我们将使用内置的 PHP 服务器，因为这是启动 WordPress 的最简单方式，并且如果需要的话，将来移动它会更容易，只要它在同一个端口上提供服务；例如，`localhost:4000`。因此，让我们找出如何做到这一点：

1.  创建一个目录（也使其可写），并在其中下载并解压 WordPress。您可以从[`wordpress.org/`](https://wordpress.org/)下载 WordPress。您应该在解压后的 WordPress 目录中看到一些带有`/wp-admin/`，`/wp-content/`和`/wp-includes/`目录的`.php`文件。

1.  通过 PHP Adminer 创建一个 MySQL 数据库（例如，`nuxt-wordpress`）。

1.  转到目录并使用内置的 PHP 提供 WordPress，如下所示：

```js
$ php -S localhost:4000
```

1.  将浏览器指向`localhost:4000`，并使用所需的 MySQL 凭据（数据库名称，用户名和密码）以及您的 WordPress 用户帐户信息（用户名，密码和电子邮件地址）安装 WordPress。

1.  使用您的用户凭据登录到`localhost:4000/wp-admin/`的 WordPress 管理 UI，并在“页面”标签下创建一些主要页面（主页，关于，项目，联系）。

1.  从**外观**下的**菜单**导航到**菜单**，通过将`menu-main`添加到**菜单名称**输入字段来创建站点导航。

1.  选择所有出现在“添加菜单项”下的页面（联系人、关于、项目、主页），然后点击“添加到菜单”将它们添加到`menu-main`作为导航项。您可以拖动和排序这些项目，使它们按照这个顺序排列：主页、关于、项目、联系人。然后，点击“保存菜单”按钮。

1.  （可选）将 WordPress 永久链接从普通选项更改为自定义结构（例如`/%postname%/`）在**永久链接**下的**设置**中。

1.  下载我们之前提到的插件并解压缩它们到`/plugins/`目录。这可以在`/wp-content/`目录中找到。然后通过管理界面激活它们。

如果您检查`nuxt-wordpress`数据库中的`wp_options`表，您应该看到端口`4000`已成功记录在`siteurl`和`home`字段中。因此，从现在开始，只要在此端口上使用内置的 PHP 服务器运行，您可以将 WordPress 项目目录移动到任何您喜欢的地方。

虽然我们在 WordPress 中有主页面和导航的数据，但我们仍然需要“项目”页面的子页面数据。我们可以将它们添加到“页面”标签，然后将它们附加到“项目”页面。但是这些页面将共享相同的内容类型（在 WordPress 中称为文章类型）-“页面”文章类型。最好将它们组织在一个单独的文章类型中，以便更容易管理。我们将在下一节中了解如何在 WordPress 中创建自定义文章类型。

有关 WordPress 安装过程的更多详细信息，请访问[`wordpress.org/support/article/how-to-install-wordpress/`](https://wordpress.org/support/article/how-to-install-wordpress/)。

## 在 WordPress 中创建自定义文章类型

我们可以从任何 WordPress 主题的`functions.php`文件中创建自定义文章类型。但是，由于我们不打算使用 WordPress 模板系统来提供我们内容的视图，我们可以从 WordPress 提供的默认主题中扩展一个**子主题**。然后，在**外观**下的**主题**中激活子主题。我们将使用“Twenty Nineteen”主题来扩展我们的子主题，然后从那里创建自定义文章类型。让我们开始吧：

1.  在`/themes/`目录中创建一个名为`twentynineteen-child`的目录，并创建一个包含以下内容的`style.css`文件：

```js
// wp-content/themes/twentynineteen-child/style.css
/*
 Theme Name: Twenty Nineteen Child
 Template: twentynineteen
 Text Domain: twentynineteenchild
*/

@import url("../twentynineteen/style.css");
```

`Theme Name`、`Template`和`Text Domain`是扩展主题的最低要求的头部注释，然后导入其父级的`style.css`文件。这些头部注释必须放在文件顶部。

如果您想在这个子主题中包含更多的头部注释，请访问[`developer.wordpress.org/themes/advanced-topics/child-themes/`](https://developer.wordpress.org/themes/advanced-topics/child-themes/)。

1.  在`/twentynineteen-child/`目录中创建一个`functions.php`文件，并使用以下格式和 WordPress 的`register_post_type`函数创建自定义文章类型，方法如下：

```js
// wp-content/themes/twentynineteen-child/functions.php
function create_something () {
    register_post_type('<name>', <args>);
}
add_action('init', 'create_something');
```

因此，要添加我们的自定义文章类型，只需将`project`作为类型名称，并提供一些参数：

```js
// wp-content/themes/twentynineteen-child/functions.php
function create_project_post_type () {
    register_post_type('project', $args);
}
add_action('init', 'create_project_post_type');
```

我们可以向自定义文章类型 UI 添加标签和我们想要支持的内容字段，方法如下：

```js
$args = [
    'labels' => [
        'name' => __('Project (Pages)'),
        'singular_name' => __('Project'),
        'all_items' => 'All Projects'
    ],
    //...
    'supports' => ['title', 'editor', 'thumbnail', 'page-attributes'],
];
```

有关`register_post_type`函数的更多信息，请访问[`developer.wordpress.org/reference/functions/register_post_type/`](https://developer.wordpress.org/reference/functions/register_post_type/)。

有关自定义文章类型 UI 的更多信息，请访问[`wordpress.org/plugins/custom-post-type-ui/`](https://wordpress.org/plugins/custom-post-type-ui/)。

1.  （可选）我们还可以为这种自定义文章类型添加对`category`和`tag`的支持，方法如下：

```js
'taxonomies' => [
    'category',
    'post_tag'
],
```

然而，这些是全局的类别和标签实例，这意味着它们与其他文章类型（如`Page`和`Post`文章类型）共享。因此，如果您想为`Project`文章类型指定特定的类别，只需使用以下代码：

```js
// wp-content/themes/twentynineteen-child/functions.php
add_action('init', 'create_project_categories');
function create_project_categories() {
    $args = [
        'label' => __('Categories'),
        'has_archive' => true,
        'hierarchical' => true,
        'rewrite' => [
            'slug' => 'project',
            'with_front' => false
        ],
    ];
    $postTypes = ['project'];
    $taxonomy = 'project-category';
    register_taxonomy($taxonomy, $postTypes, $args);
}
```

有关注册分类法的更多信息，请访问[`developer.wordpress.org/reference/functions/register_taxonomy/`](https://developer.wordpress.org/reference/functions/register_taxonomy/)。

1.  （可选）如果您发现难以使用，可能会完全禁用 Gutenberg 对所有文章类型：

```js
// wp-content/themes/twentynineteen-child/functions.php
add_filter('use_block_editor_for_post', '__return_false', 10);
add_filter('use_block_editor_for_post_type', '__return_false', 10);
```

1.  在 WordPress 管理界面中激活子主题，并开始向“项目”标签添加`project`类型页面。

您会注意到，您可以使用的内容字段（`title`、`editor`、`thumbnail`、`page-attributes`）非常有限，用于向项目页面添加内容。我们需要更多特定的内容字段，例如用于添加多个项目图片和全屏图片的内容字段。这与我们在`home`页面上遇到的问题相同，因为我们需要另一个内容字段，以便我们也可以添加多个幻灯片图片。要添加更多这些内容字段，我们将需要自定义元框。您可以使用 ACF 插件或创建自己的自定义元框并将其包含在`functions.php`文件中，或者将其创建为插件。或者，您可以使用另一个不同的元框插件，如 Meta Box ([`metabox.io/`](https://metabox.io/))。这完全取决于您。

一旦您创建了自定义内容字段并向每个项目页面添加了所需的内容，您可以扩展 WordPress REST API 以用于项目页面、主页面和导航。我们将在下一节中学习如何做到这一点。

## 扩展 WordPress REST API

WordPress REST API 可以通过`/wp-json/`访问，并且是附加到基于站点的 URL 的入口路由。例如，您可以通过将浏览器指向`localhost:4000/wp-json/`来查看所有其他可用的路由。您将看到每个路由中可用的端点，因为这些可以是 GET 或 POST 端点。例如，`/wp-json/wp/v2/pages`路由具有用于列出页面的 GET 端点和用于创建页面的 POST 端点。您可以在[`developer.wordpress.org/rest-api/reference/`](https://developer.wordpress.org/rest-api/reference/)找到有关这些默认路由和端点的更多信息。

然而，如果您有自定义的文章类型和自定义内容字段，那么您将需要自定义路由和端点。我们可以通过在`functions.php`文件中使用`register_rest_route`函数注册它们来创建这些的自定义版本，如下所示：

```js
add_action('rest_api_init', function () { , and then followed by the available endpoint
    $args = [
        'methods' => 'GET',
        'callback' => '<do_something>',
    ];
    register_rest_route(<namespace>, <route>, $args);
});
```

让我们学习如何扩展 WordPress REST API：

1.  创建用于获取导航和单个页面的全局命名空间和端点：

```js
// wp-content/themes/twentynineteen-child/functions.php
$namespace = 'api/v1/';

add_action('rest_api_init', function () use ($namespace) {
    $route = 'menu';
    $args = [
        'methods' => 'GET',
        'callback' => 'fetch_menu',
    ];
    register_rest_route($namespace, $route, $args);
});

add_action('rest_api_init', function () use ($namespace) {
    $route = 'page/(?P<slug>[a-zA-Z0-9-]+)';
    $args = [
        'methods' => 'GET',
        'callback' => 'fetch_page',
    ];
    register_rest_route($namespace, $route, $args);
});
```

请注意，我们通过在匿名函数中使用 PHP 的`use`关键字将全局命名空间传递给每个`add_action`块。有关 PHP 的`use`关键字和匿名函数的更多信息，请访问[`www.php.net/manual/en/functions.anonymous.php`](https://www.php.net/manual/en/functions.anonymous.php)。

有关 WordPress 的`register_rest_route`函数的更多信息，请访问[`developer.wordpress.org/reference/functions/register_rest_route/`](https://developer.wordpress.org/reference/functions/register_rest_route/)。

1.  为获取单个项目页面和列出项目页面创建端点：

```js
// wp-content/themes/twentynineteen-child/functions.php
add_action('rest_api_init', function () use ($namespace) {
    $route = 'project/(?P<slug>[a-zA-Z0-9-]+)';
    $args = [
        'methods' => 'GET',
        'callback' => 'fetch_project',
    ];
    register_rest_route($namespace, $route, $args);
});

add_action('rest_api_init', function () use ($namespace) {
    $route = 'projects/(?P<page_number>\d+)';
    $args = [
        'methods' => 'GET',
        'callback' => 'fetch_projects',
    ];
    register_rest_route($namespace, $route, $args);
});
```

1.  创建一个`fetch_menu`函数来获取`menu-main`导航项：

```js
// wp-content/themes/twentynineteen-child/functions.php
function fetch_menu ($data) {
    $menu_items = wp_get_nav_menu_items('menu-main');

    if (empty($menu_items)) {
        return [];
    }

    return $menu_items;
}
```

我们使用 WordPress 的`wp_get_nav_menu_items`函数来帮助我们获取导航。

有关`wp_get_nav_menu_items`函数的更多信息，请访问[`developer.wordpress.org/reference/functions/wp_get_nav_menu_items/`](https://developer.wordpress.org/reference/functions/wp_get_nav_menu_items/)。

1.  创建一个`fetch_page`函数来按 slug（或路径）获取页面：

```js
// wp-content/themes/twentynineteen-child/functions.php
function fetch_page ($data) {
    $post = get_page_by_path($data['slug'], OBJECT, 'page');

    if (!count((array)$post)) {
        return [];
    }
    $post->slides = get_field('slide_items', $post->ID);

    return $post;
}
```

在这里，我们使用 WordPress 的`get_page_by_path`函数来获取页面。有关此函数的更多信息，请访问[`developer.wordpress.org/reference/functions/get_page_by_path/`](https://developer.wordpress.org/reference/functions/get_page_by_path/)。

我们还使用 ACF 插件的`get_field`函数来获取附加到页面的幻灯片图片列表，然后将它们作为`slides`推送到`$post`对象中。有关此函数的更多信息，请访问[`www.advancedcustomfields.com/resources/get_field/`](https://www.advancedcustomfields.com/resources/get_field/)。

1.  创建一个`fetch_project`函数来获取单个项目页面：

```js
// wp-content/themes/twentynineteen-child/functions.php
function fetch_project ($data) {
    $post = get_page_by_path($data['slug'], OBJECT, 'project');

    if (!count((array)$post)) {
        return [];
    }
    $post->fullscreen = get_field('full_screen_image', $post->ID);
    $post->images = get_field('image_items', $post->ID);

    return $post;
}
```

同样，我们使用 WordPress 的`get_page_by_path`函数来为我们获取页面，并使用 ACF 的`get_field`函数来获取附加到项目页面的图片（全屏图片和项目图片），然后将它们作为`fullscreen`和`images`推送到`$post`对象中。

1.  创建一个`fetch_projects`函数来获取项目页面列表，每页 6 个项目：

```js
// wp-content/themes/twentynineteen-child/functions.php
function fetch_projects ($data) {
    $paged = $data['page_number'] ? $data['page_number'] : 1;
    $posts_per_page = 6;
    $post_type = 'project';
    $args = [
        'post_type' => $post_type,
        'post_status' => ['publish'],
        'posts_per_page' => $posts_per_page,
        'paged' => $paged,
        'orderby' => 'date'
    ];
    $posts = get_posts($args);

    if (empty($posts)) {
        return [];
    }

    foreach ($posts as &$post) {
        $post->featured_image = get_the_post_thumbnail_url($post->ID);
    }
    return $posts;
}
```

在这里，我们使用 WordPress 的`get_posts`函数以所需的参数来获取列表。有关此函数的更多信息，请访问[`developer.wordpress.org/reference/functions/get_posts/`](https://developer.wordpress.org/reference/functions/get_posts/)。

然后，我们循环每个项目页面，并将它们的特色图片推送到 WordPress 的`get_the_post_thumbnail_url`函数中。有关此函数的更多信息，请访问[`developer.wordpress.org/reference/functions/get_the_post_thumbnail_url/`](https://developer.wordpress.org/reference/functions/get_the_post_thumbnail_url/)。

1.  我们还需要计算数据（上一页编号和下一页编号），以便为项目页面进行分页，因此，不仅返回`$posts`，还要将其作为以下数组中的`items`返回，并包含分页数据：

```js
$total = wp_count_posts($post_type);
$total_max_pages = ceil($total->publish / $posts_per_page);

return [
    'items' => $posts,
    'total_pages' => $total_max_pages,
    'current_page' => (int)$paged,
    'next_page' => (int)$paged === (int)$total_max_pages ? null :
     $paged + 1,
    'prev_page' => (int) $paged === 1 ? null : $paged - 1,
];
```

在这里，我们使用`wp_count_posts`函数来计算总发布的项目页面数。有关此功能的更多信息，请访问[`developer.wordpress.org/reference/functions/wp_count_posts/`](https://developer.wordpress.org/reference/functions/wp_count_posts/)。

1.  登录 WordPress 管理界面，转到**工具**下的重写规则，并单击刷新规则按钮以刷新 WordPress 重写规则。

1.  转到浏览器，测试您刚刚创建的自定义 API 路由：

```js
/wp-json/api/v1/menu
/wp-json/api/v1/page/<slug>
/wp-json/api/v1/projects/<number>
/wp-json/api/v1/project/<slug>
```

您应该在浏览器屏幕上看到一堆 JSON 原始数据。JSON 原始数据可能很难阅读，但您可以使用**JSONLint**，一个 JSON 验证器，对您的数据进行漂亮的打印，网址是[`jsonlint.com/`](https://jsonlint.com/)。或者，您也可以使用**Firefox**，它有漂亮打印数据的选项。

您可以在本书的 GitHub 存储库中的`/chapter-18/cross-domain/backend/wordpress/`中找到此代码的全部内容。您也可以在其中找到一个示例数据库（`nuxt-wordpress.sql`）。用于登录 WordPress 管理界面的此示例数据库的默认**用户名**和**密码**是**admin**。

干得好！您已成功扩展了 WordPress REST API，以便支持自定义文章类型。我们不需要在 WordPress 中开发任何新主题来查看我们的内容，因为这将由 Nuxt 处理。我们可以保留 WordPress 的现有主题来预览内容。这意味着我们只是使用 WordPress 远程托管我们网站的内容，包括所有媒体文件（图片、视频等）。此外，我们可以使用 Nuxt 生成静态页面（就像我们在前几章中所做的那样），并从 WordPress 流式传输所有媒体文件到我们的 Nuxt 项目，以便我们可以在本地托管它们。我们将在下一节学习如何做到这一点。

## 使用 Nuxt 集成和从 WordPress 流式传输图像

将 Nuxt 与 WordPress REST API 集成类似于您在前几章中学习和创建跨域 API 集成时的操作。但是，在本节中，我们将改进我们用于加载图像的插件，通过从`/assets/`目录中要求它们来加载。但由于我们的图像是上传到 WordPress CMS 并保存在我们的 WordPress 项目的`/uploads/`目录中，因此我们需要重构我们的资产加载器插件，以便在那里找到图像时从`/assets/`目录中要求它们；否则，我们将从 WordPress 远程加载它们。让我们开始吧：

1.  在 Nuxt 配置文件中为 Axios 实例设置`remote URL`，如下所示：

```js
// nuxt.config.js
const protocol = 'http'
const host = process.env.NODE_ENV === 'production' ? 'your-domain.com' : 'localhost'
const ports = {
  local: '3000',
  remote: '4000'
}
const remoteUrl = protocol + '://' + host + ':' + ports.remote

module.exports = {
  env: {
    remoteUrl: remoteUrl,
  }
}
```

1.  创建一个 Axios 实例，并将其直接注入到 Nuxt 上下文中作为`$axios`。还可以使用`inject`函数将此 Axios 实例添加到上下文中的`app`选项中：

```js
// plugins/axios.js
import axios from 'axios'

let baseURL = process.env.remoteUrl
const api = axios.create({ baseURL })

export default (ctx, inject) => {
  ctx.$axios = api
  inject('axios', api)
}
```

1.  重新设计资产加载器插件，如下所示：

```js
// plugins/utils.js
import Vue from 'vue'

Vue.prototype.$loadAssetImage = src => {
  var array = src.split('/')
  var last = [...array].pop()
  if (process.server && process.env.streamRemoteResource === true) {
    var { streamResource } = require('~/assets/js/stream-resource')
    streamResource(src, last)
    return
  }

  try {
    return require('~/assets/images/' + last)
  } catch (e) {
    return src
  }
}
```

在这里，我们将图像 URL 字符串拆分为一个数组，从数组的最后一项中获取图像的文件名（例如`my-image.jpg`），并将其存储在`last`变量中。然后我们使用文件名（`last`）在本地获取图像。如果抛出错误，这意味着图像在`/assets/`目录中不存在，因此我们只是返回图像的 URL（`src`）。

然而，当我们的应用在服务器端运行且`streamRemoteResource`选项为`true`时，我们将使用`streamResource`函数从远程 URL 流式传输图像到`/assets/`目录。您将在接下来的步骤中了解如何创建此选项（就像`remoteURL`选项一样）。

1.  在`/assets/`目录中创建一个带有`streamResource`函数的`stream-resource.js`文件，如下所示：

```js
// assets/js/stream-resource.js
import axios from 'axios'
import fs from 'fs'

export const streamResource = async (src, last) => {
  const file = fs.createWriteStream('./assets/images/' + last)
  const { data } = await axios({
    url: src,
    method: 'GET',
    responseType: 'stream'
  })
  data.pipe(file)
}
```

在此函数中，我们使用普通的 Axios 来请求远程资源的数据，并将`stream`作为响应类型。然后，我们使用 Node.js 内置的文件系统（fs）包中的`createWriteStream`函数以及必要的文件路径来在`/assets/`目录中创建图像。

有关`fs`包及其`createWriteStream`函数的更多信息，请访问[`nodejs.org/api/fs.html`](https://nodejs.org/api/fs.html)和[`nodejs.org/api/fs.htmlfs_fs_createwritestream_path_options`](https://nodejs.org/api/fs.html#fs_fs_createwritestream_path_options)。

有关 Node.js 流的`pipe`事件和 Node.js 流本身的更多信息，请访问[`nodejs.org/api/stream.htmlstream_event_pipe`](https://nodejs.org/api/stream.html#stream_event_pipe)和[`nodejs.org/api/stream.htmlstream_stream`](https://nodejs.org/api/stream.html#stream_stream)。

1.  在 Nuxt 配置文件中注册这两个插件：

```js
// nuxt.config.js
plugins: [
  '~/plugins/axios.js',
  '~/plugins/utils.js',
],
```

1.  重构`/pages/`目录中的主页`index.vue`以使用这两个插件，如下所示：

```js
// pages/index.vue
async asyncData ({ error, $axios }) {
  let { data } = await $axios.get('/wp-json/api/v1/page/home')
  return {
    post: data
  }
}

<template v-for="slide in post.slides">
  <img :src="$loadAssetImage(slide.image.sizes.medium_large)">
</template>
```

在这里，我们使用了我们的插件中的`$axios`来请求 WordPress API。在接收到数据后，我们将其填充到`<template>`块中。`$loadAssetImage`函数用于运行关于如何加载和处理图像的逻辑。

`/pages/`目录中的其余页面应该进行重构，并遵循我们为主页所遵循的相同模式。它们是`/about.vue`、`/contact.vue`、`/projects/index.vue`、`/projects/_slug.vue`和`/projects/pages/_number.vue`。此外，你还需要对`/components/`目录中的组件进行相同的操作；也就是说，`/projects/project-items.vue`。你可以在本节末尾提供的 GitHub 存储库中找到这些已完成文件的存储库路径。

1.  在我们的 Nuxt 项目的`package.json`文件中，使用自定义环境变量`NUXT_ENV_GEN`创建另一个脚本命令，并将`stream`作为其值：

```js
// package.json
"scripts": {
  "generate": "nuxt generate",
  "stream": "NUXT_ENV_GEN=stream nuxt generate"
}
```

在 Nuxt 中，如果你在`package.json`文件中创建一个以`NUXT_ENV_`为前缀的环境变量，它将自动注入到 Node.js 进程环境中。这样做后，你可以通过`process.env`对象在整个应用程序中访问它，包括你可能在 Nuxt 配置文件的`env`属性中设置的其他自定义属性。

有关 Nuxt 中`env`属性的更多信息，请访问[`nuxtjs.org/api/configuration-env/`](https://nuxtjs.org/api/configuration-env/)。

1.  在 Nuxt 配置文件的`env`属性中为资产加载器插件（我们在*步骤 3*中重构的）定义`streamRemoteResource`选项，如下所示：

```js
// nuxt.config.js
env: {
  streamRemoteResource: process.env.NUXT_ENV_GEN === 'stream' ? 
   true : false
},
```

当我们从`NUXT_ENV_GEN`环境变量获取`stream`值时，`streamRemoteResource`选项将设置为`true`；否则，它始终设置为`false`。因此，当此选项设置为`true`时，资产加载器插件将开始将远程资源流式传输到`/assets/`目录。

1.  （可选）如果 Nuxt 爬虫由于某些未知原因无法检测到动态路由，则可以在 Nuxt 配置文件的`generate`选项中手动生成这些路由，方法如下：

```js
// nuxt.config.js 
import axios from 'axios'
export default {
  generate: {
    routes: async function () {
      const projects = await axios.get(remoteUrl + '/wp-json/api/v1/projects')
      const routesProjects = projects.data.map((project) => {
        return {
          route: '/projects/' + project.post_name,
          payload: project
        }
      })

      let totalMaxPages = Math.ceil(routesProjects.length / 6)
      let pagesProjects = []
      Array(totalMaxPages).fill().map((item, index) => {
        pagesProjects.push({
          route: '/projects/pages/' + (index + 1),
          payload: null
        })
      })

      const routes = [ ...routesProjects, ...pagesProjects ]
      return routes
    }
  }
}
```

在这个可选的步骤中，我们使用 Axios 来获取属于`projects`文章类型的所有子页面，并使用 JavaScript 的`map`方法循环这些页面以生成它们的路由。然后，我们通过将子页面除以六（每页六个项目）来计算出子页面的最大页面数（`totalMaxPages`）。然后，我们使用 JavaScript 的`Array`对象将`totalMaxPages`数字转换为数组，然后使用 JavaScript 的`fill`，`map`和`push`方法循环数组以生成分页的动态路由。最后，我们使用 JavaScript 的展开运算符将子页面和分页的路由连接起来，然后将它们作为单个数组返回，以便 Nuxt 为我们生成动态路由。

有关 JavaScript `map`，`fill`和`push`方法的更多信息，请访问[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map)，[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/fill`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/fill)，以及[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/push`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/push)。

1.  首先在终端上运行`stream`命令，然后运行`generate`命令，如下所示：

```js
$ npm run stream && npm run generate
```

我们使用`stream`命令将远程资源流式传输到`/assets/`目录，生成第一批静态页面，然后使用`generate`命令重新生成静态页面。此时，webpack 将处理`/assets/`目录中的图像，并将其与静态页面一起导出到`/dist/`文件夹中。因此，在运行这两个命令后，您应该看到远程资源在`/assets/`和`/dist/`中被流式传输和处理。您可以转到这两个目录并检查已下载的资源。

您可以在本书的 GitHub 存储库中的`/chapter-18/cross-domain/frontend/nuxt-universal/nuxt-wordpress/axios-vanilla/`中找到本节的 Nuxt 应用程序。

干得好！您已成功将 Nuxt 与 WordPress REST API 集成，并为静态页面流式传输远程资源。WordPress 可能不是每个人的选择，因为它不符合**PHP 标准建议**（**PSRs**）([`www.php-fig.org/`](https://www.php-fig.org/))，并且有其自己的完成任务的方式。但它是在 2003 年发布的，早于 PSR 和许多现代 PHP 框架。自那时以来，它已能够支持无数的企业和个人。当然，它已经发展，并为编辑和开发人员提供了最用户友好的管理 UI 之一。

如果这没有说服您使用 WordPress 作为 API，还有其他选择。在下一节中，我们将看看 REST API 的替代方案 - GraphQL API - 以及 Node.js 中 WordPress 的替代方案 - Keystone。Keystone 使用 GraphQL 来提供其 API。在深入研究 GraphQL 之前，我们将看看 Keystone，并学习如何开发定制的 CMS。

# 介绍 Keystone

Keystone 是一个可扩展的无头 CMS，用于在 Node.js 中构建 GraphQL API。它是开源的，并配备了一个非常体面的管理 UI，您可以在其中管理您的内容。就像 WordPress 一样，您可以在 Keystone 中创建称为**列表**的自定义内容类型，然后通过 GraphQL API 查询您的内容。您可以从源代码创建列表，就像创建 REST API 一样。您可以为 API 添加所需的内容，使其具有高度可扩展性和可扩展性。

使用 Keystone，首先，您需要准备一个用于存储内容的数据库。Keystone 支持 MongoDB 和 PostgreSQL。您需要安装和配置其中一个，然后找出 Keystone 的连接字符串。您在第九章中了解了 MongoDB，*添加服务器端数据库*，因此再次将其用作 Keystone 的数据库不应该成为问题。但是 PostgreSQL 呢？让我们找出来。

有关 Keystone 的更多信息，请访问[`www.keystonejs.com/`](https://www.keystonejs.com/)。

## 安装和保护 PostgreSQL（Ubuntu）

PostgreSQL，也称为 Postgres，是一种面向对象的关系数据库系统，通常与 MySQL 进行比较，后者是一种（纯粹的）关系数据库管理系统（RDBMS）。两者都是开源的，使用表格，但它们有各自的区别。

例如，Postgres 在很大程度上符合 SQL 标准，而 MySQL 在部分方面符合标准，MySQL 在读取速度方面更快，而 PostgreSQL 在注入复杂查询方面更快。有关 Postgres 的更多信息，请访问[`www.postgresql.org/`](https://www.postgresql.org/)。

您可以在许多不同的操作系统上安装 Postgres，包括 Linux、macOS 和 Windows。根据您的操作系统，您可以按照官方指南在您的计算机上安装它。我们将向您展示如何在 Linux 上安装和保护它，特别是 Ubuntu，具体步骤如下：

1.  更新您的本地软件包索引，并使用 Ubuntu 的`apt`包装系统从 Ubuntu 的默认存储库安装 Postgres：

```js
$ sudo apt update
$ sudo apt install postgresql postgresql-contrib
```

1.  通过检查其版本来验证 Postgres：

```js
$ psql -v
```

如果您获得以下输出，则表示您已成功安装：

```js
/usr/lib/postgresql/12/bin/psql: option requires an argument -- 'v'
Try "psql --help" for more information.
```

路径中的数字**12**表示您的计算机上安装了 Postgres 12 版本。

1.  从终端输入 Postgres shell：

```js
$ sudo -u postgres psql
```

您应该在终端上获得类似以下的输出：

```js
postgres@lau-desktop:~$ psql
psql (12.2 (Ubuntu 12.2-2.pgdg19.10+1))
Type "help" for help.

postgres=
```

1.  使用 Postgres 的`\du`命令列出默认用户：

```js
postgres= \du
```

您应该获得两个默认用户，如下所示：

```js
Role name 
-----------
postgres 
root
```

我们将使用终端上的交互提示向列表中添加一个新的管理用户（或角色）。但是，我们首先需要退出 Postgres shell：

```js
postgres= \q
```

1.  使用`--interactive`标志输入以下命令：

```js
$ sudo -u postgres createuser --interactive
```

关于新角色名称以及角色是否应该具有超级用户权限，您应该看到以下两个问题：

```js
Enter name of role to add: user1
Shall the new role be a superuser? (y/n) y
```

在这里，我们将新用户称为`user1`。它具有超级用户权限，就像默认用户一样。

1.  使用`sudo -u postgres psql`登录 Postgres shell 以验证新用户是否已添加到列表中。

1.  使用以下 SQL 查询为新用户添加密码：

```js
ALTER USER user1 PASSWORD 'password';
```

如果您获得以下输出，则已成功为此用户添加了密码：

```js
ALTER ROLE
```

1.  退出 Postgres shell。现在，您可以使用 PHP 的 Adminer ([`www.adminer.org/`](https://www.adminer.org/))使用此用户登录 Postgres，并在那里添加一个新的数据库，这将在稍后安装 Keystone 时需要。然后，您可以使用以下格式的 Postgres 连接字符串连接刚刚创建的数据库：

```js
postgres://<username>:<password>@localhost/<dbname>
```

请注意，出于安全原因，任何用户要从 Adminer 登录到数据库都需要密码。因此，无论是 MySQL、Postgres 还是 MongoDB 数据库，都最好添加安全性。MongoDB 呢？您在之前的章节中学习了如何安装和使用它，但尚未进行安全保护。我们将在下一节中了解如何做到这一点。

## 安装和保护 MongoDB（Ubuntu）

到目前为止，您应该知道如何安装 MongoDB。因此，在本节中，我们将专注于保护 MongoDB 中的数据库。为了保护 MongoDB，我们将首先添加一个管理用户到 MongoDB，如下所示：

1.  从终端连接到 Mongo shell：

```js
$ mongo
```

1.  选择`admin`数据库，并向该数据库添加一个具有用户名和密码（例如，root 和 password）的新用户，如下所示：

```js
> use admin
> db.createUser(
  {
    user: "root",
    pwd: "password",
    roles: [ { role: "userAdminAnyDatabase", db: "admin" }, 
     "readWriteAnyDatabase" ]
  }
)
```

1.  退出 shell 并从终端打开 MongoDB 配置文件：

```js
$ sudo nano /etc/mongod.conf
```

1.  查找`security`部分，删除哈希，并添加`authorization`设置，如下所示：

```js
// mongodb.conf
security:
  authorization: "enabled"
```

1.  保存并退出文件，然后重新启动 MongoDB：

```js
$ sudo systemctl restart mongod
```

1.  通过检查 MongoDB 的状态来验证配置：

```js
$ sudo systemctl status mongod
```

如果看到`"active"`状态，这意味着您已正确配置。

1.  使用密码和`--authenticationDatabase`选项以`"root"`身份登录。此外，在此情况下，提供存储用户的数据库的名称，即`"admin"`：

```js
$ mongo --port 27017 -u "root" -p "password" --authenticationDatabase "admin"
```

1.  创建一个新的数据库（例如，`test`）并将一个新用户附加到其中：

```js
> use test
db.createUser(
  {
    user: "user1",
    pwd: "password",
    roles: [ { role: "readWrite", db: "test" } ]
  }
)
```

1.  退出并以`user1`身份登录以测试数据库：

```js
$ mongo --port 27017 -u "user1" -p "password" --authenticationDatabase "test"
```

1.  测试是否可以访问此`test`数据库，但不能访问其他数据库：

```js
> show dbs
```

如果没有输出，这意味着您只有在经过身份验证后才有权访问此数据库。您可以使用以下格式为 Keystone 或任何其他应用程序（例如 Express、Koa 等）提供 MongoDB 连接字符串：

```js
mogodb://<username>:<password>@localhost:27017/<dbname>
```

再次强调，为数据库添加安全性是一个好习惯，尤其是对于生产环境，但在 MongoDB 中启用身份验证会使开发应用程序变得更加简单和快速。您可以在本地开发时始终禁用它，并在生产服务器上启用它。

现在，两个数据库系统（Postgres 和 MongoDB）都已准备就绪，您可以选择其中任何一个来构建 Keystone 应用程序。所以，让我们开始吧！

## 安装和创建 Keystone 应用程序

有两种方法可以启动 Keystone 项目 - 从头开始或使用称为`keystone-app`的 Keystone 搭建工具。如果您要从头开始，您需要手动安装任何与 Keystone 相关的软件包。这些包括最低要求的 Keystone 软件包和您构建应用程序所需的其他 Keystone 软件包。让我们来看看这个手动安装：

1.  创建一个项目目录并安装最低要求的软件包 - Keystone 软件包本身，Keystone GraphQL 软件包（在 Keystone 中被视为应用程序），以及数据库适配器：

```js
$ npm i @keystonejs/keystone
$ npm i @keystonejs/app-graphql
$ npm i @keystonejs/adapter-mongoose
```

1.  安装您需要的其他 Keystone 软件包，例如 Keystone Admin UI 软件包（在 Keystone 中被视为应用程序）和用于注册列表的 Keystone 字段软件包：

```js
$ npm i @keystonejs/app-admin-ui
$ npm i @keystonejs/fields
```

1.  在根目录中创建一个空的`index.js`文件，并导入您刚刚安装的软件包：

```js
// index.js
const { Keystone } = require('@keystonejs/keystone')
const { GraphQLApp } = require('@keystonejs/app-graphql')
const { AdminUIApp } = require('@keystonejs/app-admin-ui')
const { MongooseAdapter } = require('@keystonejs/adapter-mongoose')
const { Text } = require('@keystonejs/fields')
```

1.  创建 Keystone 的新实例，并将新的数据库适配器实例传递给它，如下所示：

```js
const keystone = new Keystone({
  name: 'My Keystone Project',
  adapter: new MongooseAdapter({ mongoUri: 'mongodb://localhost/your-
    db-name' }),
})
```

查看以下指南，了解如何配置 Mongoose 适配器：[`www.keystonejs.com/keystonejs/adapter-mongoose/`](https://www.keystonejs.com/keystonejs/adapter-mongoose/)。当我们使用搭建工具安装 Keystone 时，我们将再次介绍这个。

1.  创建一个简单的列表 - 例如`Page`列表，并定义您需要的字段，以便存储此列表中每个单个项目的数据：

```js
keystone.createList('Page', {
  fields: {
    name: { type: Text },
  },
})
```

对于 GraphQL，将列表的名称大写是一种惯例。我们很快会介绍这个。

1.  导出`keystone`实例和应用程序，以便可以执行它们：

```js
module.exports = {
  keystone,
  apps: [new GraphQLApp(), new AdminUIApp()]
}
```

1.  创建一个`package.json`文件（如果您还没有这样做），并添加以下`keystone`命令到脚本中，如下所示：

```js
"scripts": {
  "dev": "keystone"
}
```

1.  通过在终端上运行`dev`脚本来启动应用程序：

```js
$ npm run dev
```

您应该在终端上看到以下输出。这意味着您已成功启动了应用程序：

```js
 Command: keystone dev
✓ Validated project entry file ./index.js
✓ Keystone server listening on port 3000
✓ Initialised Keystone instance
✓ Connected to database
✓ Keystone instance is ready at http://localhost:3000
∞ Keystone Admin UI: http://localhost:3000/admin
∞ GraphQL Playground: http://localhost:3000/admin/graphiql
∞ GraphQL API: http://localhost:3000/admin/api
```

干得好！您的第一个和最简单的 Keystone 应用程序已经开始运行。在这个应用程序中，您在`localhost:3000/admin/api`上有一个 GraphQL API，在`localhost:3000/admin/graphiql`上有一个 GraphQL Playground，在`localhost:3000/admin`上有一个 Keystone Admin UI。但是我们如何使用 GraphQL API 和 GraphQL Playground 呢？放心，我们将在接下来的部分中介绍。

开始一个新的 Keystone 应用并不难，是吗？您只需要安装 Keystone 所需的内容。然而，启动 Keystone 应用的最简单方法是使用脚手架工具。使用脚手架工具的好处是，在安装过程中它附带了一些 Keystone 应用的可选示例，它们可以作为指南和模板非常有用。这些可选示例如下：

+   **入门**：这个示例演示了使用 Keystone 进行基本用户身份验证。

+   **Todo**：这个示例演示了一个简单的应用程序，用于向`Todo`列表添加项目，以及一些前端集成（HTML、CSS 和 JavaScript）。

+   **空白**：这个示例提供了一个基本的起点，以及 Keystone 管理 UI、GraphQL API 和 GraphQL Playground。这些与手动安装中的内容一样，但没有 Keystone `field`包。

+   **Nuxt**：这个示例演示了与 Nuxt.js 的简单集成。

我们将选择**空白**选项，因为它为我们提供了我们需要的基本包，这样我们就可以在其基础上构建我们的列表。让我们来看一下：

1.  在终端上创建一个任何名称的全新 Keystone 应用程序：

```js
$ npm init keystone-app <app-name>
```

1.  回答 Keystone 提出的问题，如下：

```js
✓ What is your project name?
✓ Select a starter project: Starter / Blank / Todo / Nuxt
✓ Select a database type: MongoDB / Postgre
```

1.  安装完成后，进入您的项目目录：

```js
$ cd <app-name>
```

1.  如果您正在使用安全的 Postgres，只需提供连接字符串，以及 Keystone 的用户名、密码和数据库：

```js
// index.js
const adapterConfig = { knexOptions: { connection: 'postgres://
 <username>:<password>@localhost/<dbname>' } }
```

请注意，如果您没有启用身份验证，只需从字符串中删除`<username>:<password>@`。然后，运行以下命令来安装数据库表：

```js
$ npm run create-tables
```

有关 Knex 数据库适配器的更多信息，请访问[`www.keystonejs.com/quick-start/adapters`](https://www.keystonejs.com/quick-start/adapters)或访问 knex.js 网站[`knexjs.org/`](http://knexjs.org/)。它是用于 PostgreSQL、MySQL 和 SQLite3 的查询构建器。

1.  如果您正在使用安全的 MongoDB，只需提供连接字符串，以及 Keystone 的用户名、密码和数据库：

```js
// index.js
const adapterConfig = { mongoUri: 'mogodb://<username>:<password>@localhost:27017/<dbname>' }
```

请注意，如果您没有启用身份验证，只需从字符串中删除`<username>:<password>@`。

有关 Mongoose 数据库适配器的更多信息，请访问[`www.keystonejs.com/keystonejs/adapter-mongoose/`](https://www.keystonejs.com/keystonejs/adapter-mongoose/)或访问 Mongoose [`mongoosejs.com/`](https://mongoosejs.com/)。MongoDB 本质上是一个**无模式**的数据库系统，因此该适配器用作模式解决方案，以对我们应用程序中的数据进行建模。

1.  将服务器默认端口从`3000`更改为`4000`以提供 Keystone 应用程序。您可以通过简单地将`PORT=4000`添加到`dev`脚本中来实现这一点，如下所示：

```js
// package.json
"scripts": {
  "dev": "cross-env NODE_ENV=development PORT=4000 ...",
}
```

我们将 Keystone 的端口更改为`4000`的原因是因为我们为 Nuxt 应用程序保留了端口`3000`。

1.  在我们的项目中安装`nodemon`。这将允许我们监视 Keystone 应用程序中的更改，以便它可以为我们重新加载服务器：

```js
$ npm i nodemon --save-dev
```

1.  安装此软件包后，将`nodemon --exec`命令添加到`dev`脚本中，如下所示：

```js
// package.json
"scripts": {
  "dev": "... nodemon --exec keystone dev",
}
```

有关 nodemon 的更多信息，请访问[`nodemon.io/`](https://nodemon.io/)。

1.  使用以下命令启动我们的 Keystone 应用程序的开发服务器：

```js
$ npm run dev
```

您应该在终端上看到以下输出。这意味着您已成功安装了 Keystone 应用程序：

```js
✓ Keystone instance is ready at http://localhost:4000
∞ Keystone Admin UI: http://localhost:4000/admin
∞ GraphQL Playground: http://localhost:4000/admin/graphiql
∞ GraphQL API: http://localhost:4000/admin/api
```

这与在不同端口上执行手动安装相同。在此应用程序中，您可以在`localhost:4000/admin/api`上找到 GraphQL API，在`localhost:4000/admin/graphiql`上找到 GraphQL Playground，在`localhost:4000/admin`上找到 Keystone Admin UI。在我们可以对 GraphQL API 和 GraphQL Playground 执行任何操作之前，我们必须向 Keystone 应用程序添加列表，并开始从 Keystone Admin UI 注入数据。我们将在下一节中开始向应用程序添加列表和字段。

您可以在本书的 GitHub 存储库的`/chapter-18/keystone/`中找到我们从这两种安装技术创建的应用程序。

## 创建列表和字段

在 Keystone 中，列表是模式。模式是一个具有描述我们数据的类型的数据模型。在 Keystone 中也是一样的：列表模式由具有描述其接受的数据的类型的字段组成，就像我们在手动安装中所做的那样，在那里我们有一个由单个`Text`类型的`name`字段组成的`Page`列表。

Keystone 中有许多不同的字段类型，例如`File`、`Float`、`Checkbox`、`Content`、`DateTime`、`Slug`和`Relationships`。您可以在[`www.keystonejs.com/`](https://www.keystonejs.com/)的文档中找到您需要的其余 Keystone 字段类型的信息。

要向列表添加字段及其类型，您只需在项目目录中安装包含这些字段类型的 Keystone 软件包。例如，`@keystonejs/fields`软件包包含`Checkbox`、`Text`、`Float`和`DateTime`字段类型，以及其他字段类型。您可以在[`www.keystonejs.com/keystonejs/fields/fields`](https://www.keystonejs.com/keystonejs/fields/#fields)了解其余字段类型。安装所需的字段类型软件包后，您只需导入它们，并使用 JavaScript 解构赋值来解压所需的字段类型，以便创建列表。

然而，列表可能会随着时间的推移而增长，这意味着它们可能变得混乱和难以跟上。因此，最好将列表创建在`/list/`目录中的**单独**文件中，以便更好地维护，如下所示：

```js
// lists/Page.js
const { Text } = require('@keystonejs/fields')

module.exports = {
  fields: {...},
}
```

然后，您只需将其导入到`index.js`文件中。因此，让我们找出我们构建 Keystone 应用程序所需的模式/列表和其他 Keystone 软件包。我们将要创建的列表如下：

+   用于存储主要页面（如`home`、`about`、`contact`和`projects`）的`Page`模式/列表

+   用于存储项目页面的`Project`模式/列表

+   用于存储主要和项目页面图像的`Image`模式/列表

+   用于仅存储主要页面图像的`Slide Image`模式/列表

+   用于存储站点链接的`Nav Link`模式/列表

我们将要使用的 Keystone 软件包来创建这些列表如下：

+   **静态文件应用程序**：此软件包用于提供静态文件，如图像、CSS 和 JavaScript，以便客户端可以公开访问。有关更多信息，请访问[`www.keystonejs.com/keystonejs/app-static/`](https://www.keystonejs.com/keystonejs/app-static/)。

+   **文件适配器**：此软件包用于支持`File`字段类型，该类型用于将文件上传到本地或远程基于云的位置。有关更多信息，请访问[`www.keystonejs.com/keystonejs/file-adapters/`](https://www.keystonejs.com/keystonejs/file-adapters/)。

+   **所见即所得编辑器**：此软件包用于在 Keystone Admin UI 中使用 TinyMCE 呈现所见即所得编辑器。有关此软件包的更多信息，请访问[`www.keystonejs.com/keystonejs/fields-wysiwyg-tinymce/`](https://www.keystonejs.com/keystonejs/fields-wysiwyg-tinymce/)。有关 TinyMCE 的信息，请访问[`www.tiny.cloud/`](https://www.tiny.cloud/)。

现在，让我们安装并使用它们来创建我们的列表：

1.  通过 npm 安装我们之前提到的 Keystone 软件包：

```js
$ npm i @keystonejs/app-static
$ npm i @keystonejs/file-adapters
$ npm i @keystonejs/fields-wysiwyg-tinymce
```

1.  将`@keystonejs/app-static`导入`index.js`，并定义您希望保留静态文件的路径和文件夹名称：

```js
// index.js
const { StaticApp } = require('@keystonejs/app-static');

module.exports = {
  apps: [
    new StaticApp({
      path: '/public',
      src: 'public'
    }),
  ],
}
```

1.  在`/lists/`目录中创建一个`File.js`文件。然后，使用`@keystonejs/fields`中的`File`，`Text`和`Slug`字段类型以及`@keystonejs/file-adapters`中的`LocalFileAdapter`定义`Image`列表的字段。这将允许您将文件上传到本地位置；即`/public/files/`：

```js
// lists/File.js
const { File, Text, Slug } = require('@keystonejs/fields')
const { LocalFileAdapter } = require('@keystonejs/file-adapters')

const fileAdapter = new LocalFileAdapter({
  src: './public/files',
  path: '/public/files',
})

module.exports = {
  fields: {
    title: { type: Text, isRequired: true },
    alt: { type: Text },
    caption: { type: Text, isMultiline: true },
    name: { type: Slug },
    file: { type: File, adapter: fileAdapter, isRequired: true },
  }
}
```

在上述代码中，我们定义了一系列字段（`title`，`alt`，`caption`，`name`和`file`），以便我们可以存储有关每个上传文件的元信息。在每个列表模式中都有`name`字段是一个良好的做法，以便我们可以在此字段中存储一个唯一名称，我们可以在 Keystone Admin UI 中用作标签。我们可以使用它轻松地识别每个注入的列表项。为此字段生成唯一名称，我们可以使用`Slug`类型，默认情况下，它从`title`字段生成唯一名称。

有关我们在上述代码中使用的字段类型的更多信息，请访问以下链接：

+   [`www.keystonejs.com/keystonejs/fields/src/types/file/`](https://www.keystonejs.com/keystonejs/fields/src/types/file/) 用于`File`类型

+   [`www.keystonejs.com/keystonejs/fields/src/types/text/`](https://www.keystonejs.com/keystonejs/fields/src/types/text/) 用于`Text`类型

+   [`www.keystonejs.com/keystonejs/fields/src/types/slug/`](https://www.keystonejs.com/keystonejs/fields/src/types/slug/) 用于`Slug`类型

有关`LocalFileAdapter`的更多信息，请访问[`www.keystonejs.com/keystonejs/file-adapters/localfileadapter`](https://www.keystonejs.com/keystonejs/file-adapters/#localfileadapter)。

我们的应用文件可以使用`CloudinaryFileAdapter`上传到 Cloudinary。

有关如何设置帐户以便您可以在 Cloudinary 上托管文件的更多信息，请访问[`cloudinary.com/`](https://cloudinary.com/)。

1.  在`/lists/`目录中创建一个`SlideImage.js`文件，并定义与`File.js`文件中相同的字段，还有一个额外的字段类型`Relationship`，以便您可以将幻灯片图像链接到项目页面：

```js
// lists/SlideImage.js
const { Relationship } = require('@keystonejs/fields')

module.exports = {
  fields: {
    // ...
    link: { type: Relationship, ref: 'Project' },
  },
}
```

有关`Relationship`字段的更多信息，请访问[`www.keystonejs.com/keystonejs/fields/src/types/relationship/`](https://www.keystonejs.com/keystonejs/fields/src/types/relationship/)。

1.  在`/lists/`目录中创建一个`Page.js`文件，并使用`@keystonejs/fields`和`@keystonejs/fields-wysiwyg-tinymce`中的`Text`、`Relationship`、`Slug`和`Wysiwyg`字段类型定义`Page`列表的字段，如下所示：

```js
// lists/Page.js
const { Text, Relationship, Slug } = require('@keystonejs/fields')
const { Wysiwyg } = require('@keystonejs/fields-wysiwyg-tinymce')

module.exports = {
  fields: {
    title: { type: Text, isRequired: true },
    excerpt: { type: Text, isMultiline: true },
    content: { type: Wysiwyg },
    name: { type: Slug },
    featuredImage: { type: Relationship, ref: 'Image' },
    slideImages: { type: Relationship, ref: 'SlideImage', many:
     true },
  },
}
```

在上述代码中，我们定义了一系列字段（`title`、`excerpt`、`content`、`name`、`featuredImage`和`slideImages`），以便我们可以存储将注入到此内容类型中的每个主页面的数据。请注意，我们将`featuredImage`链接到`Image`列表，并将`slideImages`链接到`SlideImage`列表。我们希望允许将多个图像放置在`slideImages`字段中，因此我们将`many`选项设置为`true`。

有关这些一对多和多对多关系的更多信息，请访问[`www.keystonejs.com/guides/new-schema-cheatsheet`](https://www.keystonejs.com/guides/new-schema-cheatsheet)。

1.  在`/lists/`目录中创建一个`Project.js`文件，并定义与`File.js`文件中的字段相同的字段，用于`Project`列表，另外再加上两个字段（`fullscreenImage`和`projectImages`）：

```js
// lists/Project.js
const { Text, Relationship, Slug } = require('@keystonejs/fields')
const { Wysiwyg } = require('@keystonejs/fields-wysiwyg-tinymce')

module.exports = {
  fields: {
    //...
    fullscreenImage: { type: Relationship, ref: 'Image' },
    projectImages: { type: Relationship, ref: 'Image', many:
     true },
  },
}
```

1.  在`/lists/`目录中创建一个`NavLink.js`文件，并使用`@keystonejs/fields`中的`Text`、`Relationship`、`Slug`和`Integer`字段类型定义`NavLink`列表的字段（`title`、`order`、`name`、`link`、`subLinks`），如下所示：

```js
// lists/NavLink.js
const { Text, Relationship, Slug, Integer } = require('@keystonejs/fields')

module.exports = {
  fields: {
    title: { type: Text, isRequired: true },
    order: { type: Integer, isRequired: true },
    name: { type: Slug },
    link: { type: Relationship, ref: 'Page' },
    subLinks: { type: Relationship, ref: 'Project', many: true },
  },
}
```

在这里，我们使用`order`字段来按照 GraphQL 查询中的数字位置对链接项进行排序。您很快就会了解这一点。`subLinks`字段是一个示例，演示了如何在 Keystone 中创建简单的子链接。因此，我们可以通过将项目页面附加到此字段来向主链接添加多个子链接，该字段使用`Relationship`字段类型与`Project`列表关联。

有关`Integer`字段类型的更多信息，请访问[`www.keystonejs.com/keystonejs/fields/src/types/integer/`](https://www.keystonejs.com/keystonejs/fields/src/types/integer/)。

1.  从`/lists/`目录导入文件，并开始从中创建列表模式，如下所示：

```js
// index.js
const PageSchema = require('./lists/Page.js')
const ProjectSchema = require('./lists/Project.js')
const FileSchema = require('./lists/File.js')
const SlideImageSchema = require('./lists/SlideImage.js')
const NavLinkSchema = require('./lists/NavLink.js')

const keystone = new Keystone({ ... })

keystone.createList('Page', PageSchema)
keystone.createList('Project', ProjectSchema)
keystone.createList('Image', FileSchema)
keystone.createList('SlideImage', SlideImageSchema)
keystone.createList('NavLink', NavLinkSchema)
```

1.  通过在终端上运行`dev`脚本启动应用程序：

```js
$ npm run dev
```

您应该在终端上看到与上一节中显示的相同的 URL 列表。这意味着您已成功在`localhost:4000`上启动了该应用程序。因此，现在，您可以将浏览器指向`localhost:4000/admin`，并开始从 Keystone Admin UI 注入内容和上传文件。一旦您准备好内容和数据，就可以使用 GraphQL API 和 GraphQL Playground 进行查询。但在这样做之前，您应该了解什么是 GraphQL 以及如何独立于 Keystone 创建和使用它。所以，让我们找出来！

您可以在本书的 GitHub 存储库中的`/chapter-18/cross-domain/backend/keystone/`中找到此应用程序的源代码。

# 介绍 GraphQL

GraphQL 是一种开放源查询语言、服务器端运行时（执行引擎）和规范（技术标准）。但这意味着什么？它是什么？GraphQL 是一种查询语言，这就是 GraphQL 中“QL”部分的含义。具体来说，它是一种客户端查询语言。但再次，这意味着什么？以下示例将解决您对 GraphQL 查询的任何疑问：

```js
{
 planet(name: "earth") {
   id
   age
   population
 }
}
```

像前面的那样的 GraphQL 查询在 HTTP 客户端（如 Nuxt 或 Vue）中使用，以交换 JSON 响应发送查询到服务器，如下所示：

```js
{
  "data": {
    "planet": {
      "id": 3,
      "age": "4543000000",
      "population": "7594000000"
    }
  }
}
```

正如您所看到的，您获取了您请求的字段（`age`和`population`）的特定数据，而不多不少。这就是使 GraphQL 与众不同的地方，它赋予客户端精确请求他们想要的能力。这很酷，很令人兴奋，不是吗？但是在服务器上返回 GraphQL 响应的是什么？一个 GraphQL API 服务器（服务器端运行时）。

GraphQL 查询由客户端通过 HTTP 端点发送到 GraphQL API 服务器，使用`POST`方法将查询作为字符串发送到服务器。服务器提取并处理查询字符串。然后，就像任何典型的 API 服务器一样，GraphQL API 将从数据库或其他服务/ API 获取数据并以 JSON 响应返回给客户端。

那么，我们可以将 Express 等服务器用作 GraphQL API 服务器吗？是和否。所有合格的 GraphQL 服务器必须实现 GraphQL 规范中指定的两个核心组件，用于验证、处理和返回数据：模式和解析器。

GraphQL 模式是一组类型定义的集合，其中包括客户端可以请求的对象以及对象具有的字段。另一方面，GraphQL 解析器是附加到字段的函数，在客户端进行查询或突变时返回值。例如，以下是查找行星的类型定义：

```js
type Planet {
  id: Int
  name: String
  age: String
  population: String
}

type Query {
  planet(name: String): Planet
}
```

在这里，您可以看到 GraphQL 使用了强类型模式 - 每个字段必须用可以是标量类型（即可以是整数、布尔值或字符串的单个值）或对象类型定义。`Planet`和`Query`类型是对象类型，而`String`和`Int`是标量类型。对象类型中的每个字段都必须通过函数解析，如下所示：

```js
Planet: {
  id: (root, args, context, info) => root.id,
  name: (root, args, context, info) => root.name,
  age: (root, args, context, info) => root.age,
  population: (root, args, context, info) => root.population,
}

Query: {
  planet: (root, args, context, info) => {
    return planets.find(planet => planet.name === args.name)
  },
}
```

前面的示例是用 JavaScript 编写的，但是 GraphQL 服务器可以用任何编程语言编写，只要您遵循并实现了 GraphQL 规范中概述的内容。以下是不同语言中的一些 GraphQL 实现的示例：

+   GraphQL.js（JavaScript）在[`github.com/graphql/graphql-js`](https://github.com/graphql/graphql-js)

+   graphql-php（PHP）在[`github.com/webonyx/graphql-php`](https://github.com/webonyx/graphql-php)

+   Graphene（Python）在[`github.com/graphql-python/graphene`](https://github.com/graphql-python/graphene)

+   GraphQL Ruby（Ruby）在[`github.com/rmosolgo/graphql-ruby`](https://github.com/rmosolgo/graphql-ruby)

只要符合 GraphQL 规范，您可以自由创建新的实现，但是在本书中我们只会使用 GraphQL.js。现在，您可能有一些更深入的问题 - 查询类型到底是什么？我们知道它是一个`object`类型，但为什么我们需要它？我们需要在模式中拥有它吗？简短的答案是是。

我们将在下一节中更详细地讨论这个问题，并找出为什么无论如何都需要它。我们还将找出如何将 Express 用作 GraphQL API 服务器。所以，请继续阅读。

## 理解 GraphQL 模式和解析器

在前一节中，我们讨论了查找行星的示例模式和解析器，假设我们使用 GraphQL 模式语言，这有助于我们创建 GraphQL 服务器所需的 GraphQL 模式。我们可以使用 Node.js 包 GraphQL Tools 中的`makeExecutableSchema`函数从 GraphQL 模式语言轻松创建一个 GraphQL.js `GraphQLSchema`实例。

您可以在[`www.graphql-tools.com/`](https://www.graphql-tools.com/)或[`github.com/ardatan/graphql-tools`](https://github.com/ardatan/graphql-tools)找到有关此包的更多信息。

GraphQL 模式语言是一种“快捷方式” - 一种用于构建 GraphQL 模式和其类型系统的简写符号。在使用这种简写符号之前，我们应该看一下 GraphQL 模式是如何从低级对象和函数（如`GraphQLObjectType`、`GraphQLString`、`GraphQLList`等）构建的，这些函数来自实现了 GraphQL 规范的 GraphQL.js。让我们安装这些包并使用 Express 创建一个简单的 GraphQL API 服务器：

1.  通过 npm 安装 Express、GraphQL.js 和 GraphQL HTTP 服务器中间件：

```js
$ npm i express
$ npm i express-graphql
$ npm i graphql
```

GraphQL HTTP 服务器中间件是一种中间件，允许我们使用任何实现了 Connect 支持中间件的 HTTP Web 框架（如 Express、Restify 和 Connect 本身）创建 GraphQL HTTP 服务器。

有关这些包的更多信息，请访问以下链接：

+   [`github.com/graphql/express-graphql`](https://github.com/graphql/express-graphql) 用于 GraphQL HTTP 服务器中间件

+   [`github.com/senchalabs/connect`](https://github.com/senchalabs/connect) 用于 Connect

+   [`expressjs.com/`](https://expressjs.com/) 用于 Express

+   [`restify.com/`](http://restify.com/) 用于 Restify

1.  在项目的根目录下创建一个`index.js`文件，并使用`require`方法导入`express`、`express-graphql`和`graphql`：

```js
// index.js
const express = require('express')
const graphqlHTTP = require('express-graphql')
const graphql = require('graphql')

const app = express()
const port = process.env.PORT || 4000
```

1.  创建一个包含行星列表的虚拟数据：

```js
// index.js
const planets = [
  { id: 3, name: "earth", age: 4543000000, population:
    7594000000 },
  { id: 4, name: "mars", age: 4603000000, population: 0 },
]
```

1.  定义`Planet`对象类型以及客户端可以查询的字段：

```js
// index.js
const planetType = new graphql.GraphQLObjectType({
  name: 'Planet',
  fields: {
  id: { ... },
  name: { ... },
  age: { ... },
  population: { ... },
})
```

注意，在 GraphQL 模式创建时，将对象类型在`name`字段中大写是一种约定。

1.  定义各种类型以及如何解析每个字段的值：

```js
// index.js
id: {
  type: graphql.GraphQLInt,
  resolve: (root, orgs, context, info) => root.id,
},
name: {
  type: graphql.GraphQLString,
  resolve: (root, orgs, context, info) => root.name,
},
age: {
  type: graphql.GraphQLString,
  resolve: (root, orgs, context, info) => root.age,
},
population: {
  type: graphql.GraphQLString,
  resolve: (root, orgs, context, info) => root.population,
},
```

注意，每个解析器函数都接受以下四个参数：

+   `root`：从父对象类型（*步骤 6*中的查询）解析出的对象或值。

+   `args`：如果设置了，字段可以接收的参数。见*步骤 8*。

+   `context`：一个可变的 JavaScript 对象，保存着所有解析器之间共享的顶层数据。在我们使用 Express 时，默认情况下是 Node.js 的 HTTP 请求对象（`IncomingMessage`）。我们可以修改这个上下文对象，并添加我们想要共享的一般数据，比如认证和数据库连接。见*步骤 10*。

+   `info`：一个 JavaScript 对象，包含有关当前字段的信息，例如字段名称、返回类型、父类型（在本例中为`Planet`）和一般模式详细信息。

如果它们对于解析当前字段的值不需要，我们可以省略它们。

1.  定义`Query`对象类型和客户端可以查询的字段：

```js
// index.js
const queryType = new graphql.GraphQLObjectType({
  name: 'Query',
  fields: {
    hello: { ... },
    planet: { ... },
  },
})
```

1.  定义类型并解析您希望返回`hello`字段的值：

```js
// index.js
hello: {
  type: graphql.GraphQLString,
  resolve: (root, args, context, info) => 'world',
}
```

1.  定义类型并解析您希望返回`planet`字段的值：

```js
// index.js
planet: {
  type: planetType,
  args: {
    name: { type: graphql.GraphQLString }
  },
  resolve: (root, args, context, info) => {
    return planets.find(planet => planet.name === args.name)
  },
}
```

请注意，我们将创建并存储在`planetType`变量中的`Planet`对象类型传递给`Query`对象类型中的`planet`字段，以便它们之间可以建立关系。

1.  使用所需的`query`字段和您刚刚定义的带有字段、类型、参数和解析器的**`Query`**对象类型构造一个 GraphQL 模式实例，如下所示：

```js
// index.js
const schema = new graphql.GraphQLSchema({ query: queryType })
```

请注意，必须提供`query`键作为 GraphQL 查询根类型，以便我们的查询可以链接到`Planet`对象类型中的字段。我们可以说`Planet`对象类型是`Query`对象类型（根类型）的子类型或子对象，并且它们的关系必须在父对象（`Query`）中使用`planet`字段中的`type`字段来建立。

1.  使用 GraphQL HTTP 服务器中间件作为中间件与 GraphQL 模式实例一起，在 Express 允许的端点上建立 GraphQL 服务器，称为`/graphiql`，如下所示：

```js
// index.js
app.use(
  '/graphiql',
  graphqlHTTP({ schema, graphiql: true }),
)
```

建议将`graphiql`选项设置为`true`，以便在浏览器加载 GraphQL 端点时可以使用 GraphQL IDE。

在这个顶层，您还可以使用`graphqlHTTP`中间件内的`context`选项修改您的 GraphQL API 的上下文，如下所示：

```js
context: {
  something: 'something to be shared',
}
```

通过这样做，您可以从任何解析器中访问这个顶层数据。这可能非常有用。很酷，不是吗？

1.  最后，在加载所有数据后，在终端上使用`node index.js`命令启动服务器，并在`index.js`文件中添加以下行：

```js
// index.js
app.listen(port)
```

1.  将浏览器指向`localhost:4000/graphiql`。您应该看到 GraphQL IDE，一个 UI，您可以在其中测试您的 GraphQL API。因此，在左侧的输入区域中键入以下查询：

```js
// localhost:4000/graphiql
{
  hello
  planet (name: "earth") {
    id
    age
    population
  }
}
```

当您点击播放按钮时，您应该看到前面的 GraphQL 查询已经在右侧与 JSON 对象交换：

```js
// localhost:4000/graphiql
{
  "data": {
    "hello": "world",
    "planet": {
      "id": 3,
      "age": "4543000000",
      "population": "7594000000"
    }
  }
}
```

干得好 - 你已经成功地使用低级方法在 Express 中创建了一个基本的 GraphQL API 服务器！我们希望这给了你一个完整的图景，了解了如何使用 GraphQL 模式和解析器创建 GraphQL API 服务器。我们也希望你能看到 GraphQL 中这两个核心组件之间的关系，并且我们已经回答了你的问题；也就是说，`Query`类型到底是什么？我们为什么需要它？我们需要在模式中拥有它吗？答案是肯定的，查询（对象）类型是一个根对象类型（通常称为根`Query`类型），在创建 GraphQL 模式时必须提供。

但是您可能仍然有一些问题和抱怨，特别是关于解析器 - 您肯定会觉得在`Planet`对象类型的字段中定义解析器在*步骤 5*中是乏味和愚蠢的，因为它们除了返回从查询对象解析的值之外什么也不做。有没有办法避免这种痛苦的重复？答案是肯定的：您不需要为模式中的每个字段指定它们，这就是**默认解析器**。但是我们该如何做呢？我们将在下一节中找到答案。

您可以在本书的 GitHub 存储库中的`/chapter-18/graphql-api/graphql-express/`中找到此类示例和其他示例。

## 理解 GraphQL 默认解析器

当没有为字段指定解析器时，默认情况下，该字段将采用在幕后由父对象解析的对象的属性的值 - 也就是说，如果该对象具有与字段名称匹配的属性名称。因此，可以将`Planet`对象类型中的字段重构如下：

```js
fields: {
  id: { type: graphql.GraphQLInt },
  name: { type: graphql.GraphQLString },
  age: { type: graphql.GraphQLString },
  population: { type: graphql.GraphQLString },
}
```

这些字段的值将回退到在幕后由父对象（查询类型）解析的对象的属性中，如下所示：

```js
root.id
root.name
root.age
root.population
```

换句话说，当为字段明确指定解析器时，即使父解析器为该字段返回任何值，此解析器也将始终被使用。例如，让我们为`Planet`对象类型中的`id`字段明确指定一个值，如下所示：

```js
fields: {
  id: {
    type: graphql.GraphQLInt,
    resolve: (root, orgs, context, info) => 2,
  },
}
```

我们已经知道地球和火星的默认 ID 值分别为 3 和 4，并且它们由`Query`对象类型（父对象）解析，如前一节的*步骤 8*所示。但这些解析的值将永远不会被使用，因为它们被 ID 的解析器覆盖了。因此，让我们查询地球或火星，如下所示：

```js
{
  planet (name: "mars") {
    id
  }
}
```

在这种情况下，您将始终在 JSON 响应中获得`2`：

```js
{
  "data": {
    "planet": {
      "id": 2
    }
  }
}
```

这非常聪明，不是吗？它可以避免我们痛苦的重复 - 也就是说，如果你在对象类型中有大量字段的话。然而，到目前为止，我们一直在用最痛苦的方式来构建我们的模式，通过使用 GraphQL.js。这是因为我们想要看到并理解 GraphQL 模式是如何从低级类型创建的。在现实生活中，我们可能不想走这么漫长和曲折的道路，特别是在一个大项目中。相反，我们应该倾向于使用 GraphQL 模式语言来为我们构建模式和解析器。在下一节中，我们将向您展示如何使用 GraphQL 模式语言和 Apollo Server 轻松创建 GraphQL API 服务器，作为 GraphQL HTTP 服务器中间件的替代方案。所以，请继续阅读！

## 使用 Apollo Server 创建 GraphQL API

Apollo Server 是 Apollo 平台开发的符合 GraphQL 规范的开源服务器，用于构建 GraphQL API。我们可以单独使用它，也可以与其他 Node.js web 框架一起使用，比如 Express、Koa、Hapi 等等。在本书中，我们将直接使用 Apollo Server，但如果您想在其他框架中使用它，请访问[`github.com/apollographql/apollo-server#installation-integrations`](https://github.com/apollographql/apollo-server#installation-integrations)。

在这个 GraphQL API 中，我们将创建一个服务器，通过标题和作者查询一系列书籍。让我们开始吧：

1.  通过 npm 安装 Apollo Server 和 GraphQL.js 作为项目依赖：

```js
$ npm i apollo-server
$ npm i graphql
```

1.  在项目根目录中创建一个`index.js`文件，并从`apollo-server`包中导入`ApolloServer`和`gql`函数：

```js
// index.js
const { ApolloServer, gql } = require('apollo-server')
```

`gql`函数用于解析 GraphQL 操作和模式语言，通过使用模板文字标签（或标记模板文字）将它们包装起来。有关模板文字和标记模板的更多信息，请访问[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals)。

1.  创建以下静态数据，其中包含作者和帖子的列表：

```js
// index.js
const authors = [
  { id: 1, name: 'author A' },
  { id: 2, name: 'author B' },
]

const posts = [
  { id: 1, title: 'Post 1', authorId: 1 },
  { id: 2, title: 'Post 2', authorId: 1 },
  { id: 3, title: 'Post 3', authorId: 2 },
]
```

1.  定义`Author`、`Post`和`Query`对象类型，以及客户端可以查询的字段：

```js
// index.js
const typeDefs = gql`
  type Author {
   id: Int
   name: String
  }

  type Post {
   id: Int
   title: String
   author: Author
  }

  type Query {
    posts: [Post]
  }
`
```

请注意，我们可以将`Author`，`Post`和`Query`对象类型简写为`Author`类型，`Post`类型和`Query`类型。这比使用“对象类型”来描述它们更清晰，因为它们就是这样。请记住，除了天生是对象类型之外，`Query`类型还是 GraphQL 模式创建中的根类型。

注意我们如何建立`Author`与`Post`以及`Post`与`Query`之间的关系 - `author`字段的类型是`Author`类型。`Author`类型的字段（`id`，`name`）是简单的标量类型，而`Post`类型的字段（`id`，`title`）和`Author`类型（`author`）是简单的标量类型。`Query`类型只有一个字段，即`posts`，它是一个帖子列表，因此我们必须使用类型修饰符，用开放和关闭的方括号包裹`Post`类型，以指示这个`posts`字段将解析为一个`Post`对象数组。

有关类型修饰符的更多信息，请访问[`graphql.org/learn/schema/lists-and-non-null`](https://graphql.org/learn/schema/#lists-and-non-null)。

1.  定义解析器以指定如何解析`Query`类型中的`posts`字段和`Post`类型中的`author`字段的值：

```js
// index.js
const resolvers = {
  Query: {
    posts: (root, args, context, info) => posts
  },

  Post: {
    author: root => authors.find(author => author.id === 
     root.authorId)
  },
}
```

注意 GraphQL 模式语言如何帮助我们将解析器与对象类型解耦，并且它们只是在单个 JavaScript 对象中简单定义。JavaScript 对象中的解析器与对象类型“神奇”地连接在一起，只要解析器的属性名称与类型定义中的字段名称相匹配。因此，这个 JavaScript 对象被称为解析器映射。在定义解析器之前，我们还必须在解析器映射中定义顶级属性名称（`Query`，`Post`），以便它们与类型定义中的对象类型（`Author`，`Post`，`Query`）匹配。但是，在这个解析器映射中，我们不需要为`Author`类型定义任何特定的解析器，因为`Author`中字段（`id`，`name`）的值会自动由默认解析器解析。

另一个需要注意的地方是`Post`类型中字段（`id`，`title`）的值也是由默认解析器解析的。如果您不喜欢使用属性名称来定义解析器，您可以改用解析器函数，只要函数名称与类型定义中的字段名称对应即可。例如，`author`字段的解析器可以重写如下：

```js
Post: {
  author (root) {
    return authors.find(author => author.id === root.authorId)
  },
}
```

1.  使用`ApolloServer`从类型定义和解析器构建一个 GraphQL 模式实例。然后，启动服务器，如下所示：

```js
// index.js
const server = new ApolloServer({ typeDefs, resolvers })

server.listen().then(({ url }) => {
  console.log(`Server ready at ${url}`)
})
```

1.  使用终端上的`node`命令启动您的 GraphQL API：

```js
$ node index.js
```

1.  将浏览器指向`localhost:4000`。您应该在屏幕上看到加载的 GraphQL Playground。从那里，您可以测试您的 GraphQL API。因此，请在左侧的输入区域中输入以下查询：

```js
{
  posts {
    title
    author {
      name
    }
  }
}
```

当您点击播放按钮时，您应该看到前面的 GraphQL 查询已经在右侧与 JSON 对象交换：

```js
{
  "data": {
    "posts": [
      {
        "title": "Post 1",
        "author": {
          "name": "author A"
        }
      },
      ...
    ]
  }
}
```

这是美好而美妙的，不是吗？这就是我们如何使用 GraphQL 模式语言和 Apollo Server 轻松构建 GraphQL API。在采用速记方法之前，了解创建 GraphQL 模式和解析器的漫长而痛苦的方式是值得的。一旦您掌握了这些基本的具体知识，您应该能够轻松查询您使用 Keystone 存储的数据。在本书中，我们只涵盖了 GraphQL 的一些类型，包括标量类型、对象类型、查询类型和类型修改器。还有一些其他类型您应该查看，例如变异类型、枚举类型、联合和输入类型以及接口。请在[`graphql.org/learn/schema/`](https://graphql.org/learn/schema/)上查看它们。

如果您想了解更多关于 GraphQL 的信息，请访问[`graphql.org/learn/`](https://graphql.org/learn/)。有关 Apollo Server 的更多信息，请访问[`www.apollographql.com/docs/apollo-server/`](https://www.apollographql.com/docs/apollo-server/)。

您可以在本书的 GitHub 存储库的`/chapter-18/graphql-api/graphql-apollo/`中找到本节中使用的代码，以及其他示例 GraphQL 类型定义。

现在，让我们学习如何使用 Keystone GraphQL API。

## 使用 Keystone GraphQL API

Keystone GraphQL API 的 GraphQL Playground 位于`localhost:4000/admin/graphiql`。在这里，我们可以在 Keystone 管理 UI 中测试我们创建的列表，位于`localhost:4000/admin`。Keystone 将为**每个**创建的列表自动生成四个顶级 GraphQL 查询。例如，我们将在上一节中创建的`page`列表中获得以下查询：

+   `allPages`

此查询可用于从`Page`列表中获取所有项目。我们还可以搜索、限制和过滤结果，如下所示：

```js
{
  allPages (orderBy: "name_DESC", skip: 0, first: 6) {
    title
    content
  }
}
```

+   `_allPagesMeta`

此查询可用于获取`Page`列表中所有项目的所有元信息，例如所有匹配项目的总计数，这对分页可能很有用。我们还可以搜索、限制和过滤结果，如下所示：

```js
{
  _allPagesMeta (search: "a") {
    count
  }
}
```

+   `Page`

此查询可用于从`Page`列表中获取单个项目。我们**只能**使用带有`id`键的`where`参数来获取页面，如下所示：

```js
{
  Page (where: { id: $id }) {
    title
    content
  }
}
```

+   `_PagesMeta`

此查询可用于获取有关`Page`列表本身的元信息，例如其名称、访问权限、模式和字段，如下所示：

```js
{
  _PagesMeta {
    name
    access {
      read
    }
    schema {
      queries
      fields {
        name
      }
    }
  }
}
```

正如您所看到的，这四个查询以及过滤器、限制和排序参数为我们提供了足够的能力来获取我们需要的特定数据，而不多。更重要的是，在 GraphQL 中，我们可以通过**单个**请求获取**多个**资源，如下所示：

```js
{
  _allPagesMeta {
    count
  },
  allPages (orderBy: "name_DESC", skip: 0, first: 6) {
    title
    content
  }
}
```

这很神奇和有趣，不是吗？在 REST API 中，您可能需要向多个 API 端点发送多个请求以获取多个资源。GraphQL 为我们提供了一个解决这个困扰前端和后端开发人员的 REST API 的替代方案。请注意，这四个顶级查询也适用于我们创建的其他列表，包括`Project`、`Image`和`NavLink`。

关于这四个顶级查询以及过滤器、限制和排序参数的更多信息，以及本书未涵盖的 GraphQL 变异和执行步骤，请访问[`www.keystonejs.com/guides/intro-to-graphql/`](https://www.keystonejs.com/guides/intro-to-graphql/)。

如果您想了解如何一般查询 GraphQL 服务器，请访问[`graphql.org/learn/queries/`](https://graphql.org/learn/queries/)。

现在您已经对 GraphQL 有了基本了解，并且了解了 Keystone 的顶级 GraphQL 查询，现在是时候学习如何在 Nuxt 应用程序中使用它们了。

# 集成 Keystone、GraphQL 和 Nuxt

Keystone 的 GraphQL API 端点位于`localhost:4000/admin/api`。与通常具有多个端点的 REST API 不同，GraphQL API 通常具有**一个单一端点**用于所有查询。因此，我们将使用此端点从 Nuxt 应用程序发送我们的 GraphQL 查询。在前端应用程序中，始终在 GraphQL Playground 上测试我们的查询以确认我们获得所需的结果，然后在前端应用程序中使用这些经过测试的查询是一个良好的做法。此外，我们应该始终在前端应用程序的查询中使用`query`关键字来从 GraphQL API 中获取数据。

在这个练习中，我们将重构为 WordPress API 构建的 Nuxt 应用程序。我们将查看`/pages/index.vue`、`/pages/projects/index.vue`、`/pages/projects/_slug.vue`和`/store/index.js`文件。我们仍然将使用 Axios 来帮助我们发送 GraphQL 查询。让我们看看如何让 GraphQL 查询和 Axios 一起工作：

1.  创建一个变量来存储 GraphQL 查询，以获取首页的标题和我们附加的幻灯片图片：

```js
// pages/index.vue
const GET_PAGE = `
  query {
    allPages (search: "home") {
      title
      slideImages {
        alt
        link {
          name
        }
        file {
          publicUrl
        }
      }
    }
  }
`
```

我们只需要从图片链接到的项目页面中获取 slug，因此`name`字段是我们要查询的唯一字段。我们只需要图片文件对象的相对公共 URL，因此`publicUrl`字段是我们想要的唯一字段。此外，我们使用`allPages`查询而不是`Page`，因为通过 slug 获取页面更容易，而在这种情况下 slug 是*home*。

1.  使用 Axios 的`post`方法将查询发送到 GraphQL API 端点：

```js
// pages/index.vue
export default {
  async asyncData ({ $axios }) {
    let { data } = await $axios.post('/admin/api', {
      query: GET_PAGE
    })
    return {
      post: data.data.allPages[0]
    }
  },
}
```

请注意，我们只需要从 GraphQL API 返回的数据中获取数组中的第一项，因此我们使用`0`来定位这第一项。

请注意，我们还应该重构`/pages/about.vue`、`/pages/contact.vue`、`/pages/projects/index.vue`和`/pages/projects/pages/_number.vue`，遵循我们重构首页的相同模式。你可以在本节末尾找到这本书的 GitHub 存储库的路径，其中包含完整的代码。

1.  创建一个变量来存储查询，并允许你从端点获取多个资源，如下所示：

```js
// components/projects/project-items.vue
const GET_PROJECTS = `
  query {
    _allProjectsMeta {
      count
    }
    allProjects (orderBy: "name_DESC", skip: ${ skip }, first: ${ 
     postsPerPage }) {
      name
      title
      excerpt
      featuredImage {
        alt
        file {
          publicUrl
        }
      }
    }
  }
`
```

正如你所看到的，我们通过`_allProjectsMeta`获取项目页面的总数，并通过`allProjects`以及`orderBy`、`skip`和`first`过滤器获取项目页面的列表。`skip`和`first`过滤器的数据将作为变量传入；分别是`skip`和`postsPerPage`。

1.  从路由参数计算`skip`变量的数据，将`6`设置为`postsPerPage`变量，然后使用 Axios 的`post`方法将查询发送到 GraphQL API 端点：

```js
// components/projects/project-items.vue
data () {
  return {
    posts: [],
    totalPages: null,
    currentPage: null,
    nextPage: null,
    prevPage: null,
  }
},

async fetch () {
  const postsPerPage = 6
  const number = this.$route.params.number
  const pageNumber = number === undefined ? 1 : Math.abs(
    parseInt(number))
  const skip = number === undefined ? 0 : (pageNumber - 1) 
   * postsPerPage

  const GET_PROJECTS = `... `

  let { data } = await $axios.post('/admin/api', {
    query: GET_PROJECTS
  })

  //... continued in step 5.
}
```

正如您所看到的，我们从路由参数中的`this.$route.params`中访问`pageNumber`数据，然后在`fetch`方法中计算出来。`skip`数据是在将其传递给 GraphQL 查询并获取数据之前，从`pageNumber`和`postsPerPage`中计算出来的。在`/projects`或`/projects/pages/1`路由上，我们将得到`1`作为`pageNumber`和`0`作为`skip`，在`/projects/pages/2`路由上，我们将得到`2`作为`pageNumber`和`6`作为`skip`，依此类推。此外，我们必须确保路由中的任何有意的负数据（例如`/projects/pages/-100`）都将使用 JavaScript 的`Math.abs`函数转换为正数。

有关 JavaScript 的`Math.abs`函数的更多信息，请访问[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/abs`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/abs)。

1.  从服务器返回的`count`字段创建分页（下一页和上一页），然后像往常一样返回数据给`<template>`块，如下所示：

```js
// components/projects/project-items.vue
let totalPosts = data.data._allProjectsMeta.count
let totalMaxPages = Math.ceil(totalPosts / postsPerPage)

this.posts = data.data.allProjects
this.totalPages = totalMaxPages
this.currentPage = pageNumber
this.nextPage = pageNumber === totalMaxPages ? null : pageNumber + 1
this.prevPage = pageNumber === 1 ? null : pageNumber - 1
```

1.  创建一个变量，用于存储从端点按`slug`获取单个项目页面的查询，如下所示：

```js
// pages/projects/_slug.vue
const GET_PAGE = `
  query {
    allProjects (search: "${ params.slug }") {
      title
      content
      excerpt
      fullscreenImage { ... }
      projectImages { ... }
    }
  }
`
```

在这里，我们通过`search`过滤器从`params.slug`参数中传递数据来获取项目页面。我们将在`fullscreenImage`和`fullscreenImage`中查询的字段与`featuredImage`中的字段相同；您可以在*步骤 3*中找到它们。

1.  使用 Axios 的`post`方法将查询发送到 GraphQL API 端点：

```js
// pages/projects/_slug.vue
async asyncData ({ params, $axios }) {
  const GET_PAGE = `...`

  let { data: { data: result } } = await $axios.post('/admin/api', 
   {
    query: GET_PAGE
  })

  return {
    post: result.allProjects[0],
  }
}
```

请注意，您还可以解构嵌套对象或数组并将变量分配给值。在前面的代码中，我们已经将`result`分配为变量，以便存储 GraphQL 返回的`data`属性的值。

1.  创建一个变量，用于存储从带有`orderBy`过滤器的端点获取`NavLinks`列表的查询，如下所示：

```js
// store/index.js
const GET_LINKS = `
  query {
    allNavLinks (orderBy: "order_ASC") {
      title
      link {
        name
      }
    }
  }
`
```

1.  使用 Axios 的`post`方法将查询发送到 GraphQL API 端点，然后将数据提交到存储状态：

```js
// store/index.js
async nuxtServerInit({ commit }, { $axios }) {
  const GET_LINKS = `...`
  let { data } = await $axios.post('/admin/api', {
    query: GET_LINKS
  })
  commit('setMenu', data.data.allNavLinks)
}
```

1.  （可选）就像*在与 Nuxt 集成并从 WordPress 流式传输图像*部分的*步骤 9*一样，如果 Nuxt 爬虫由于某些未知原因无法检测到动态路由，那么在 Nuxt 配置文件的生成选项中手动生成这些路由，如下所示：

```js
// nuxt.config.js
import axios from 'axios'

export default {
  generate: {
    routes: async function () {
      const GET_PROJECTS = `
        query {
          allProjects { name }
        }
      `
      const { data } = await axios.post(remoteUrl + '/admin/api', {
        query: GET_PROJECTS
      })
      const routesProjects = data.data.allProjects.map(project => {
        return {
          route: '/projects/' + project.name,
          payload: project
        }
      })

      let totalMaxPages = Math.ceil(routesProjects.length / 6)
      let pagesProjects = []
      Array(totalMaxPages).fill().map((item, index) => {
        pagesProjects.push({
          route: '/projects/pages/' + (index + 1),
          payload: null
        })
      })

      const routes = [ ...routesProjects, ...pagesProjects ]
      return routes
    }
  },
}
```

在这个可选步骤中，您可以看到我们使用相同的 JavaScript 内置对象和方法 - `Array`，`map`，`fill`和`push`，就像在*与 Nuxt 集成并从 WordPress 流式传输图像*部分中一样，为我们解决子页面的动态路由和分页，然后将它们作为单个数组返回给 Nuxt 生成它们的动态路由。

1.  运行以下脚本命令，无论是开发还是生产：

```js
$ npm run dev
$ npm run build && npm run start
$ npm run stream && npm run generate
```

请记住，如果您想生成静态页面并将图像托管在同一位置，我们有能力将远程图像流式传输到`/assets/`目录，以便 webpack 可以为我们处理这些图像。因此，如果您想这样做，那么就像我们之前做的那样，首先运行`npm run stream`将远程图像流式传输到本地磁盘，然后运行`npm run generate`重新生成带有图像的静态页面，然后将它们托管在某个地方。

您可以在本书的 GitHub 存储库中的`/chapter-18/cross-domain/frontend/nuxt-universal/nuxt-keystone`中找到此练习的代码。

除了使用 Axios，您还可以使用 Nuxt Apollo 模块向服务器发送 GraphQL 查询。有关此模块及其用法的更多信息，请访问[`github.com/nuxt-community/apollo-module`](https://github.com/nuxt-community/apollo-module)。

干得好！您已成功将 Nuxt 与 Keystone GraphQL API 集成，并为静态页面流式传输远程资源 - 就像您在 WordPress REST API 中所做的那样。我们希望 Keystone 和 GraphQL 特别是向您展示了另一个令人兴奋的 API 选项。您甚至可以进一步利用本章学到的 GraphQL 知识，为 Nuxt 应用程序开发自己的 GraphQL API。您还可以通过本书介绍的许多其他技术，将 Nuxt 提升到更高的水平。这本书是一次相当艰难的旅程。我们希望它对您的 Web 开发有所裨益，并且您可以将从本书中学到的知识应用到更广泛的领域。现在，让我们总结一下您在本章学到的内容。

# 摘要

在这一章中，您成功创建了自定义文章类型和路由，以扩展 WordPress REST API，并与 Nuxt 集成，并从 WordPress 流式传输远程资源以生成静态页面。您还成功通过创建列表和字段来定制了 Keystone 的 CMS。然后，您学会了如何使用 GraphQL.js 在低级别创建 GraphQL API，并使用 GraphQL 模式语言和 Apollo Server 在高级别创建 GraphQL API。现在您已经掌握了 GraphQL 的基础知识，可以使用 GraphQL 查询和 Axios 从 Nuxt 应用程序查询 Keystone GraphQL API。最后，您还可以从 Keystone 项目流式传输远程资源到 Nuxt 项目以生成静态页面。干得好！

这是一个非常漫长的旅程。您从了解 Nuxt 的目录结构到添加页面、路由、过渡、组件、Vuex 存储、插件和模块，然后到创建用户登录和 API 身份验证，编写端到端测试，并创建 Nuxt SPA（静态页面）。您还将 Nuxt 与其他技术、工具和框架集成，包括 MongoDB、RethinkDB、MySQL、PostgreSQL 和 GraphQL；Koa、Express、Keystone 和 Socket.IO；PHP 和 PSRs；Zurb Foundation 和 Less CSS；以及 Prettier、ESLint 和 StandardJS。

我们希望这是一个激励人心的旅程，希望您在项目中采用 Nuxt，并进一步发展，使自己和社区受益。继续编码，激发灵感，保持激励。祝您一切顺利。

请注意，本书的最终应用程序示例可以在作者的网站上找到。这是一个完全由 Nuxt 的`static`目标和 GraphQL 制作的静态生成的网络应用程序！请查看并在[`lauthiamkok.net/`](https://lauthiamkok.net/)上探索。
