package com.ashis.springblog.service;

import com.ashis.springblog.dto.PostDto;
import com.ashis.springblog.exception.PostNotFoundException;
import com.ashis.springblog.model.Post;
import com.ashis.springblog.model.User;
import com.ashis.springblog.repository.PostRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class PostService {

    @Autowired
    PostRepository postRepository;

    @Autowired
    AuthService authService;

    public List<PostDto> showAllPosts() {
        List<Post> posts = postRepository.findAll();
        return posts.stream().map(this::mapFromPostToDto).collect(Collectors.toList());
    }

    private PostDto mapFromPostToDto(Post post) {
        PostDto postDto = new PostDto();
        postDto.setId(post.getId());
        postDto.setTitle(post.getTitle());
        postDto.setContent(post.getContent());
        postDto.setUsername(post.getUsername());
        return postDto;
    }

    public void createPost(PostDto postDto) {
        Post post = mapFromDtoToPost(postDto);
        postRepository.save(post);
    }

    public PostDto readSinglePost(Long id) {
        Post post = postRepository.findById(id).orElseThrow(() -> new PostNotFoundException("For id" + id));
        return mapFromPostToDto(post);
    }

    private Post mapFromDtoToPost(PostDto postDto) {
        Post post = new Post();
        post.setTitle(postDto.getTitle());
        post.setContent(postDto.getContent());
//        User loggedInUser
        String userName = authService.getCurrentUser()
                        .orElseThrow(() -> new IllegalArgumentException("User Not Found")).getUsername();
        post.setCreatedOn(Instant.now());
//        post.setUsername(loggedInUser.getUserName());
        post.setUsername(userName);
        post.setUpdateOn(Instant.now());
        return post;
    }
}
