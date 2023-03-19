module Jekyll
  class TagPageGenerator < Generator
    priority :lowest

    def generate(site)
      site.tags.each do |tag, posts|
        site.pages << TagPage.new(site, tag, tag.downcase + "/index.html")
      end
    end
  end

  class TagPage < Page
    def initialize(site, tag, filename)
      @site = site
      @tag = tag
      @dir = File.join("tag", tag.downcase)
      @filename = filename

      self.process(@filename)
      self.read_yaml(File.join(site.source, '_layouts'), "tag.html")
      self.data['tag'] = @tag

      tag_title_prefix = site.config['tag_title_prefix'] || 'Posts tagged: '
      self.data['title'] = "#{tag_title_prefix}#{@tag}"

      self.data['posts'] = site.tags[@tag]
    end
  end
end
