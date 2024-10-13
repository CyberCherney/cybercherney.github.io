---
layout: frontpage
---

<h1>Posts</h1>
<ul class="post-list">
  {% for post in site.posts %}
  <li class="post-list-li">
    <span class="post-date">{{ post.date | date: '%b %-d, %Y' }}</span>
    <h2 class="post-title">
      <a href="{{ post.url }}">
        {{ post.title }}
      </a>
    </h2>
    <span class="tag-list">
      tags: 
      {% for tag in post.tags %}
        <a href="/tags#{{ tag }}" data-proofer-ignore>{{ tag }}</a> 
      {% endfor %}
    </span>
    <p><br>
    <a href="{{ post.url }}">
      <img src="{{ post.icon }}" alt="box icon" style="float: right; height: 95px; margin-top: -110px;">
    </a>
    {{ post.post_description }}
    </p>
  </li>
  {% endfor %}
</ul>
