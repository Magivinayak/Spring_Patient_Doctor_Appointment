package com.example.Patient_Doctor_Application.repository;

import com.example.Patient_Doctor_Application.entity.AppointmentEntity;
import com.example.Patient_Doctor_Application.entity.DoctorEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AppointmentRepository extends JpaRepository<AppointmentEntity,Long> {

    long countByDoctorId(Long doctorId);

    AppointmentEntity findByFullName(String fullName);

    AppointmentEntity findByDoctorId(Long doctorId);

}
