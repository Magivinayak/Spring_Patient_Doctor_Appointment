package com.example.Patient_Doctor_Application.controller;

import com.example.Patient_Doctor_Application.entity.AppointmentEntity;
import com.example.Patient_Doctor_Application.entity.CommentEntity;
import com.example.Patient_Doctor_Application.entity.DoctorEntity;
import com.example.Patient_Doctor_Application.entity.UserEntity;
import com.example.Patient_Doctor_Application.service.AppointmentService;
import com.example.Patient_Doctor_Application.service.CommentService;
import com.example.Patient_Doctor_Application.service.DoctorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Optional;

@Controller
public class AppointmentController {

    @Autowired
    private AppointmentService appointmentService;

    @Autowired
    private DoctorService doctorService;

    @Autowired
    private CommentService commentService;

    // Register User Page
    @GetMapping("/userRegister")
    public String userRegister(Model model) {
        model.addAttribute("registerPatient", new UserEntity());
        return "patientRegister";
    }

    // Register User Data Processing
    @PostMapping("/newPatient")
    public String addPatient(@ModelAttribute("registerPatient") UserEntity userEntity) {
        appointmentService.createNewUser(userEntity);
        return "redirect:/patientHome";
    }

    // Register Appointment Page
    @GetMapping("/appointmentRegister/{id}")
    public String appointmentRegister(@PathVariable("id") Long doctorId, Model model,RedirectAttributes redirectAttributes) {
        Optional<DoctorEntity> optionalDoctor = doctorService.getDoctorById(doctorId);
        if (optionalDoctor.isPresent()) {
            DoctorEntity doctorEntity = optionalDoctor.get();
            AppointmentEntity appointmentEntity = new AppointmentEntity();
            appointmentEntity.setDoctorName(doctorEntity.getFullName());
            appointmentEntity.setDoctorId(doctorEntity.getDoctorId());
            model.addAttribute("registerAppointment", appointmentEntity);
            model.addAttribute("doctorEntity", doctorEntity);
            return "appointmentForm";
        } else {
            redirectAttributes.addFlashAttribute("errorMessage","Error occurred while booking appointment");
            return "redirect:/errorPage"; //  return an appropriate error view
        }
    }

    // Register Appointment Data Processing
    @PostMapping("/appointment")
    public String addAppointment(@ModelAttribute("registerAppointment") AppointmentEntity appointmentEntity, RedirectAttributes redirectAttributes) {
        appointmentService.createAppointment(appointmentEntity, appointmentEntity.getDoctorId());
        redirectAttributes.addFlashAttribute("email", appointmentEntity.getEmail());
        return "redirect:/patientHome";
    }

    // User Home Page
    @GetMapping("/patientHome")
    public String userDashboard(@ModelAttribute("email") String email,Model model,RedirectAttributes redirectAttributes) {
        try {
            List<DoctorEntity> doctorEntities = doctorService.getAllDoctors();//commentService.getAllComments();
            List<CommentEntity> commentEntities = commentService.getCommentByEmail(email);
            long totalDoctors = doctorService.countTotalDoctor();
            long totalSpecialists = doctorEntities.stream()
                    .filter(doctor -> !"General Physician".equals(doctor.getSpecialist()))
                    .count();
            model.addAttribute("totalDoctors", totalDoctors);
            model.addAttribute("totalSpecialists", totalSpecialists);
            model.addAttribute("doctorDetails", doctorEntities);
            model.addAttribute("commentDetails", commentEntities);
            return "patientHome";
        } catch (Exception e) {
            // Handle exception,
            redirectAttributes.addFlashAttribute("errorMessage", "An error occurred while loading the Patient dashboard.");
            return "redirect:/errorPage";
        }
    }
}
