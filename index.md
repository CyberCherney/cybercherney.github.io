---
layout: frontpage
---

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
      {% for tag in post.tags %}
        <a>{{ tag }}</a> 
      {% endfor %}
    </span>
    <p><br>
    {{ post.content | strip_html | truncatewords:75}}
    </p>
  </li>
  {% endfor %}
</ul>
