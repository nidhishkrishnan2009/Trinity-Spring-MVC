package com.test;

import org.springframework.stereotype.Controller;

import org.springframework.ui.Model;

import org.springframework.ui.ModelMap;

import org.springframework.web.bind.annotation.PathVariable;

import org.springframework.web.bind.annotation.RequestMapping;

import org.springframework.web.bind.annotation.RequestMethod;

@Controller

public class GreetController {

    @RequestMapping(path= "/greet/{name}",method=RequestMethod.GET)    

    public String greet(@PathVariable String name, ModelMap model){

        String greet =" Hello !!!" + name + " How are You?";

        model.addAttribute("greet", greet);

        System.out.println(greet);

        

        return "greet";

    }

    
    @RequestMapping(path= "/",method=RequestMethod.GET)    

    public String home( ModelMap model){

        String greet =" Hello !!! How are You?";

        //model.addAttribute("greet", greet);

        System.out.println(greet);

        

        return "login";

    }
    
    @RequestMapping(path= "/login",method=RequestMethod.GET)    

    public String login( ModelMap model){

        String greet =" Hello !!! How are You?";

        //model.addAttribute("greet", greet);

        System.out.println(greet);

        

        return "home";

    }
}