package com.example.Patient_Doctor_Application.controller;

import com.example.Patient_Doctor_Application.entity.AppointmentEntity;
import com.example.Patient_Doctor_Application.entity.ContactEntity;
import com.example.Patient_Doctor_Application.entity.DoctorEntity;
import com.example.Patient_Doctor_Application.service.AppointmentService;
import com.example.Patient_Doctor_Application.service.ContactService;
import com.example.Patient_Doctor_Application.service.DoctorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
public class LoginController {

    @Autowired
    private DoctorService doctorService;

    @Autowired
    private AppointmentService appointmentService;

    @Autowired
    private ContactService contactService;

    // Home page
    @GetMapping("/")
    public String home() {
        return "index";
    }

    // About page
    @GetMapping("/about")
    public String about() {
        return "about";
    }

    // Contact page
    @GetMapping("/contact")
    public String contact(Model model) {
        model.addAttribute("createContact", new ContactEntity());
        return "contactUs";
    }

    @PostMapping("/saveContact")
    public String saveContactForm(@ModelAttribute("createContact") ContactEntity contactEntity) {
        contactService.saveContact(contactEntity);
        return "redirect:/";
    }

    @GetMapping("/userLoginForm")
    public String patientLogin() {
        return "patientLogin";
    }

    @PostMapping("/userLogin")
    public String patientLoginData(@RequestParam("email") String email, @RequestParam("password") String password,
                                   RedirectAttributes redirectAttributes) {
        try {
            redirectAttributes.addFlashAttribute("email", email);

            return "redirect:/patientHome";
        } catch (Exception e) {
            // Handle exception
            redirectAttributes.addFlashAttribute("errorMessage", "Error occurred while login to Patient Dashboard");

            return "redirect:/errorPage"; // or return an appropriate error view
        }
    }

    // error page
    @GetMapping("/errorPage")
    public String error() {
        return "errorPage";
    }
}
