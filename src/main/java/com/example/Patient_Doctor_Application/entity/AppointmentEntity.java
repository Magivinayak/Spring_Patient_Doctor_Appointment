package com.example.Patient_Doctor_Application.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AppointmentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long appId;

    private Long userId;
    private String fullName;
    private String gender;
    private String age;
    private String appointmentDate;
    private String email;
    private String phone;
    private String address;
    private String diseases;
    private Long doctorId;
    private String doctorName;
    private String status;
}
