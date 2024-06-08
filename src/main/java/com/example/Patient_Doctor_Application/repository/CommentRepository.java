package com.example.Patient_Doctor_Application.repository;

import com.example.Patient_Doctor_Application.entity.CommentEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CommentRepository extends JpaRepository<CommentEntity,Long> {

    List<CommentEntity> findByEmail(String email);
}
