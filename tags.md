---
layout: frontpage
title: Tags
---


<h1>Tags</h1>

<div class="search-bar">
  <input type="text" id="search-tags" placeholder="Search tags..." style="color:#fff;">
</div>

{% assign sorted_tags = site.tags | sort %}

{% for tag in sorted_tags %}
  <h2 id="{{ tag[0] }}">{{ tag[0] }}</h2>
  <ul>
    {% for post in tag[1] %}
      <li class="post {{ tag[0] }}">
        <a href="{{ post.url }}">{{ post.title }}</a>
      </li>
    {% endfor %}
  </ul>
{% endfor %}

<script>
  // Search tags based on user input
  function searchTags() {
    var input = document.getElementById("search-tags");
    var filter = input.value.toLowerCase();
    var tags = document.getElementsByTagName("h2");

    for (var i = 0; i < tags.length; i++) {
      if (tags[i].id.toLowerCase().indexOf(filter) > -1) {
        tags[i].style.display = "";
      } else {
        tags[i].style.display = "none";
      }
    }

    var posts = document.getElementsByClassName("post");

    for (var i = 0; i < posts.length; i++) {
      var tags = posts[i].classList;
      var match = false;

      for (var j = 0; j < tags.length; j++) {
        if (tags[j] !== "post" && tags[j].indexOf(filter) > -1) {
          match = true;
          break;
        }
      }

      if (match) {
        posts[i].style.display = "";
      } else {
        posts[i].style.display = "none";
      }
    }
  }

  // Scroll to tag based on URL hash
  function scrollToTag() {
    var hash = window.location.hash.substring(1);
    if (hash) {
      var tag = document.getElementById(hash);
      if (tag) {
        tag.scrollIntoView();
      }
    }
  }

  // Attach search bar and scroll event listeners
  document.getElementById("search-tags").addEventListener("keyup", searchTags);
  window.addEventListener("hashchange", scrollToTag);
  window.addEventListener("load", scrollToTag);
</script>
