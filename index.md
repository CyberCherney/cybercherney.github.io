---
layout: frontpage
---

  {% for post in site.posts %}
  <article>
    <span class="post-date">{{ post.date | date: '%b %-d, %Y' }}<br></span>
    <span class="post-title">
      <a href="{{ post.url }}">
        {{ post.title }}
      </a>
    </span>
    <span><br>test</span>
    <p>{{ post.excerpt }}
    {% if post.content contains site.excerpt_separator %}
      <a href="{{ site.baseurl }}{{ post.url }}">Read more</a>
    {% endif %}
    </p>
  </article>
{% endfor %}

