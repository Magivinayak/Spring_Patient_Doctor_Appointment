package com.example.Patient_Doctor_Application.service;

import com.example.Patient_Doctor_Application.entity.CommentEntity;
import com.example.Patient_Doctor_Application.repository.CommentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CommentService {

    @Autowired
    private CommentRepository commentRepository;

    // Save Comment
    public CommentEntity saveComment(CommentEntity commentEntity) {
        return commentRepository.save(commentEntity);
    }

    // Get All Comments
    public List<CommentEntity> getAllComments() {
        return commentRepository.findAll();
    }

    public List<CommentEntity> getCommentByEmail(String email){
        return commentRepository.findByEmail(email);
    }
}
