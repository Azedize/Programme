export const gmail_process = {
    "login": [

        {"action": "check_if_exist", "xpath":"//a[starts-with(@href,'https://accounts.google.com/AccountChooser')] | //input[@id='identifierId'] | //div[@id='gbwa'] | //div[@id='main-message']", "wait": 6, "sleep": 0,
            //div[@id='gbwa']  deja connecter sur boi de reception 
            "sub_action": [
                {"action": "check_if_exist", "xpath":"//a[starts-with(@href,'https://accounts.google.com/AccountChooser')]", "wait": 1, "sleep": 0,
                    "sub_action": [
                        {"action": "click", "xpath": "//a[starts-with(@href,'https://accounts.google.com/AccountChooser')]", "sleep": 0, "wait": 5}
                    ]
                }, 
                {"action": "check_if_exist", "xpath": "//input[@id='identifierId']", "wait": 1,"sleep": 0,
                    "sub_action": [
                        {"action": "send_keys", "xpath": "//input[@id='identifierId']", "value": __email__ , "wait": 1, "sleep": 1},
                        {"id":1,"action": "press_keys", "xpath": "//button[.//span[text()='Suivant']] | //button[.//span[text()='Next']]", "wait": 1, "sleep": 5 ,
                            "sub_action": [

                                {"action": "check_if_exist", "xpath": "(//a[@aria-label='Try to restore' or @aria-label='Essayer de restaurer']) | (//form//div[contains(text(), 'robot')])", "wait": 7,"sleep": 0,
                                     "sub_action":[
                                        {"action": "check_if_exist", "xpath": "//a[@aria-label='Try to restore' or @aria-label='Essayer de restaurer']", "wait": 1,"sleep": 0, 
                                            "sub_action": [
                                                {"action": "check_if_exist", "xpath": "//a[@aria-label='Try to restore' or @aria-label='Essayer de restaurer']", "wait": 1, "sleep": 0 ,   "obligatoire":true , "type":"account_restore"},   // restore account 
                                            ]
                                        }
                                        , 
                                        {"action": "check_if_exist", "xpath": "//form//div[contains(text(), 'robot')]", "wait": 1,"sleep": 0, 
                                            "sub_action": [
                                                {"action": "check_if_exist", "xpath": "//form//div[contains(text(), 'robot')]", "wait": 1, "sleep": 0 ,   "obligatoire":true , "type":"validation_capcha"},   // validation capcha 
                                            ]
                                        }      
                                    ]
                                }
                                                      
                            ]
                        },
                        {"action": "send_keys", "xpath": "//input[@type='password']", "value":__password__, "wait": 15, "sleep": 1},
                        {"id":2,"action": "press_keys", "xpath": "//button[.//span[text()='Suivant']] | //button[.//span[text()='Next']]",  "wait": 1, "sleep": 3 ,
                            "sub_action": [

                                {"action": "check_if_exist", "xpath": "//div[@aria-live='polite']//div[@aria-hidden='true']/following-sibling::div//span | (//a[(text()='En savoir plus' or  text()='Learn more')]) | //input[@id='knowledgePreregisteredEmailInput']", "wait": 3,"sleep": 0, 

                                    "sub_action": [
                                        {"action": "check_if_exist", "xpath": "//div[@aria-live='polite']//div[@aria-hidden='true']/following-sibling::div//span", "wait": 3,"sleep": 0, 
                                            "sub_action": [
                                                {"action": "check_if_exist", "xpath": "//div[@aria-live='polite']//div[@aria-hidden='true']/following-sibling::div//span", "wait": 2, "sleep": 0 , "obligatoire":true , "type":"password_changed"},   // Le mot de passe est incorrect
                                            ]
                                        },                           
                        
                                        {"action": "check_if_exist", "xpath": "//a[(text()='En savoir plus' or  text()='Learn more')]", "wait": 1,"sleep": 0, 
                                            "sub_action": [
                                                {"action": "check_if_exist", "xpath": "//a[(text()='En savoir plus' or  text()='Learn more')]", "wait": 1, "sleep": 0 , "obligatoire":true , "type":"Activite_suspecte"},   // Activité suspecte
                                            ]
                                        },
                                        
                                        {"action": "check_if_exist", "xpath": "//input[@id='knowledgePreregisteredEmailInput']", "wait": 1,"sleep": 0, 
                                            "sub_action": [
                                                {"action": "check_if_exist", "xpath": "//input[@id='knowledgePreregisteredEmailInput']", "wait": 1, "sleep": 0 , "obligatoire":true , "type":" code_de_validation"},   // code de validation
                                            ]
                                        }
                                    ]
                                }  
                                
                            ]
                        },

                        {"action": "check_if_exist", "xpath": "(//div[@data-challengeid])[last()]", "wait": 3, "sleep": 2,  // pour recovry if exist 
                            "sub_action": [
                                {"action": "click", "xpath": "(//div[@data-challengeid])[last()]" ,"wait": 1, "sleep": 5},
                                {"action": "send_keys", "xpath": "//input[@id='knowledge-preregistered-email-response']", "value":__recovry__,"wait": 1,"sleep": 0}, //pour input recovry 
                                {"id":3,"action": "press_keys", "xpath": "//button[.//span[text()='Suivant']] | //button[.//span[text()='Next']]", "wait": 1, "sleep": 3 ,  
                                    "sub_action": [
                                        {"action": "check_if_exist", "xpath": "//div[@aria-live='polite']//div[@aria-hidden='true']/following-sibling::div//span", "wait": 3,"sleep": 0, 
                                            "sub_action": [
                                                {"action": "check_if_exist", "xpath": "//div[@aria-live='polite']//div[@aria-hidden='true']/following-sibling::div//span", "wait": 2, "sleep": 0  , "obligatoire":true , "type":"recovry_incorrect"},   //Le recovry est incorrect
                                            ]
                                        }                            
                                    ]
                                }
                            ]
                        }
                    ]
                },

                {"action": "check_if_exist", "xpath":"//div[@id='main-message']", "wait": 1, "sleep": 0,
                    "sub_action": [
                        {"action": "click", "xpath": "//div[@id='main-message']", "sleep": 0, "wait": 5 , "obligatoire":true , "type":"bad_proxy"}
                    ]
                }, 

                //   arrete ici pas triter pourqui 
                {"action": "check_if_exist", "xpath": "//div[@data-secondary-action-label='Not now']|//div[@data-secondary-action-label='Pas maintenant']", "wait": 3,"sleep": 0, //div Not now 
                    "sub_action": [
                        {"action": "click", "xpath": "//div[@data-secondary-action-label='Not now']/div/div[2]/div/div/button|//div[@data-secondary-action-label='Pas maintenant']/div/div[2]/div/div/button", "wait": 2, "sleep": 0},   //button  Not now 
                    ]
                }
              
            ]
        }
    ],
    "report_spam": [
        {"action": "dispatchEvent", "xpath": "//div[@gh='mtb']/div/div[2]/div[2]", "wait": 3, "sleep": 3},
        {"action": "check_if_exist", "xpath": "//button[span[text()='Report spam'] or span[text()='Spam']]", "wait": 2,"sleep": 0, 
            "sub_action": [
                {"action": "click", "xpath": "//button[span[text()='Report spam'] or span[text()='Spam']]", "wait": 2, "sleep": 0},  
            ]
        }
    ],
    "delete": [
        {"action": "dispatchEvent", "xpath": "//div[@gh='mtb']/div/div[2]/div[3] | //div[@gh='mtb']/div/div/div[2]/div[3]", "wait": 3, "sleep": 3}
    ],
    "not_spam": [
        {"action": "dispatchEvent", "xpath": "(//div[@gh='mtb']/div/div[count(div)=2][1]/div[1][count(div)=1] | //div[@gh='mtb']/div/div[count(div)=1][3]/div[1] | //div[@gh='mtb']/div[count(div)=1]/div/div[count(div)=1][3]/div[1] | //div[@gh='mtb']/div[count(div)=1]/div/div[count(div)=2]/div[1])[1]", "wait": 3, "sleep": 3}
    ],
    "click_link": [
        {"action": "search_for_link_and_click", "xpath": "(//div[@data-message-id])[1]/div[2]/div[3]/div[3]/div[1]//a[@href]", "wait": 10, "sleep": 3},    ],
    "open_inbox": [
        {"action": "open_url", "url": "https://mail.google.com/mail/u/0/#inbox", "wait": 1, "sleep": 5},
    ],
    "open_spam": [
        {"action": "open_url", "url": "https://mail.google.com/mail/u/0/#spam", "wait": 1, "sleep": 5},

    ],
    "archive": [
      {"action": "dispatchEvent", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[2]/div[1]", "wait": 5, "sleep": 1}
    ],
    "next": [
        {"action": "check_if_exist", "xpath": "//div[@class='nH bkK']/div/div/div/div[@class='aeH']/div[@gh]/div[2]/div[1]/div/div[2][@role='button' and not(@aria-disabled='true')]", "wait": 1, "sleep": 0,
         "sub_action": [
             {"action": "click", "xpath": "//div[@class='nH bkK']/div/div/div/div[@class='aeH']/div[@gh]/div[2]/div[1]/div/div[2][@role='button' and not(@aria-disabled='true')]", "wait": 1, "sleep": 0}
         ]}
    ],
    "next_page": [
        {"action": "check_if_exist", "xpath": "//div[@gh]/div[@class='nH aqK']/div[@class='Cr aqJ']/div[1]/span/div[3][@role='button' and not(@aria-disabled)]", "wait": 1, "sleep": 0,
             "sub_action": [
                 {"action": "dispatchEvent", "xpath": "//div[@gh]/div[@class='nH aqK']/div[@class='Cr aqJ']/div[1]/span/div[3][@role='button' and not(@aria-disabled)]", "wait": 1, "sleep": 0}
             ]}
    ],
    "CHECK_NEXT": [   //next page
        {"action": "check", "xpath": "//div[@gh]/div[@class='nH aqK']/div[@class='Cr aqJ']/div[1]/span/div[3][@role='button' and not(@aria-disabled)] | //div[@class='nH bkK']/div/div/div/div[@class='aeH']/div[@gh]/div[2]/div[1]/div/div[2][@role='button' and not(@aria-disabled='true')]", "wait": 1, "sleep": 0}
    ],
    "CHECK_FOLDER": [  //check sur message 
        {"action": "check", "xpath": "(//div[@role='main' and @class]//div[@jsaction]//table/tbody/tr[1]/td[@role='gridcell'])[1]", "wait": 5, "sleep": 1}
    ],
    "is_empty_folder": [
        {"action": "check", "xpath": "(//div[@role='main' and @class]//div[@jsaction]//table/tbody/tr[1]/td[@role='gridcell'])[1]", "wait": 5, "sleep": 1}
    ],
    "is_last_message": [  //last message 
        {"action": "check", "xpath": "//div[@class='nH bkK']/div/div/div/div[@class='aeH']/div[@gh]/div[2]/div[1]/div/div[2][@role='button' and (@aria-disabled='true')]", "wait": 5, "sleep": 1}
    ],
    "open_message": [
        {"action": "click", "xpath": "(//div[@role='main' and @class]//div[@jsaction]//table/tbody/tr[1]/td[@role='gridcell'])[1]", "wait": 10, "sleep": 1}
    ],
    "OPEN_MESSAGE_ONE_BY_ONE": [
        {"action": "click", "xpath": "(//div[@role='main' and @class]//div[@jsaction]//table/tbody/tr[1]/td[@role='gridcell'])[1]", "wait": 10, "sleep": 1}
    ],

    "search": [
        {"action": "send_keys", "xpath": "//input[@name='q']", "value": "__search__", "wait": 5, "sleep": 1},
        {"action": "press_keys", "xpath": '//button[@aria-label="Rechercher dans les messages" and @role="button"] | //button[@aria-label="Search mail" and @role="button"]', "wait": 1, "sleep": 7}
    ],
    "select_all": [
        {"action": "dispatchEvent", "xpath": "//div[@class='Cq aqL' and @gh='mtb']/div/div/div/div/div/div[@aria-hidden='true']", "wait": 10, "sleep": 1 },
        {"action": "dispatchEventTwo", "xpath": "//div/div[@gh='tm']//div[@selector='all' and @role='menuitem']", "wait": 3, "sleep": 1}
    ],
    "mark_as_important": [
        {"action": "dispatchEvent", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[@class='G-Ni J-J5-Ji'][last()]/div[@role='button']", "wait": 5, "sleep": 0},
        {"action": "check_if_exist", "xpath": "//div[@role='menu' and @aria-haspopup='true' and not(contains(@style,'display: none;'))]/div[@class='SK AX']/div[28][@role='menuitem']", "wait": 1, "sleep": 0,
         "sub_action": [
             {"action": "dispatchEventTwo", "xpath": "//div[@role='menu' and @aria-haspopup='true' and not(contains(@style,'display: none;'))]/div[@class='SK AX']/div[28][@role='menuitem']", "wait": 1, "sleep": 1},
             {"action": "dispatchEvent", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[@class='G-Ni J-J5-Ji'][last()]/div[@role='button']", "wait": 5, "sleep": 1},
         ]},
        {"action": "check_if_exist", "xpath": "//div[@role='menu' and @aria-haspopup='true' and not(contains(@style,'display: none;'))]/div[@class='SK AX']/div[4][not(@aria-disabled='true')]", "wait": 1, "sleep": 0,
         "sub_action": [
             {"action": "dispatchEventTwo", "xpath": "//div[@role='menu' and @aria-haspopup='true' and not(contains(@style,'display: none;'))]/div[@class='SK AX' ]/div[4][not(@aria-disabled='true')]", "wait": 2, "sleep": 0}
         ]},
        {"action": "check_if_exist", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[@class='G-Ni J-J5-Ji'][last()]/div[@role='button' and @aria-expanded='true']", "wait": 1, "sleep": 0,
         "sub_action": [
             {"action": "dispatchEvent", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[@class='G-Ni J-J5-Ji'][last()]/div[@role='button' and @aria-expanded='true']", "wait": 1, "sleep": 0}
         ]}
    ],
    "add_star": [
        {"action": "dispatchEvent", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[@class='G-Ni J-J5-Ji'][last()]/div[@role='button']", "wait": 5, "sleep": 1},
        {"action": "check_if_exist", "xpath": "//div[@role='menu' and @aria-haspopup='true' and not(contains(@style,'display: none;'))]/div[@class='SK AX']/div[28][@role='menuitem']", "wait": 1, "sleep": 0,
         "sub_action": [
             {"action": "dispatchEventTwo", "xpath": "//div[@role='menu' and @aria-haspopup='true' and not(contains(@style,'display: none;'))]/div[@class='SK AX']/div[28][@role='menuitem']", "wait": 1, "sleep": 1},
             {"action": "dispatchEvent", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[@class='G-Ni J-J5-Ji'][last()]/div[@role='button']", "wait": 5, "sleep": 1},
         ]},
        {"action": "check_if_exist", "xpath": "//div[@role='menu' and @aria-haspopup='true' and not(contains(@style,'display: none;'))]/div[@class='SK AX']/div[7][not(@aria-disabled='true')]", "wait": 1, "sleep": 0,
         "sub_action": [
             {"action": "dispatchEventTwo", "xpath": "//div[@role='menu' and @aria-haspopup='true' and not(contains(@style,'display: none;'))]/div[@class='SK AX']/div[7][not(@aria-disabled='true')]", "wait": 2, "sleep": 0}
         ]},
        {"action": "check_if_exist", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[@class='G-Ni J-J5-Ji'][last()]/div[@role='button' and @aria-expanded='true']", "wait": 1, "sleep": 0,
         "sub_action": [
             {"action": "dispatchEvent", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[@class='G-Ni J-J5-Ji'][last()]/div[@role='button' and @aria-expanded='true']", "wait": 1, "sleep": 0}
         ]}
    ],
    "mark_as_read": [
        {"action": "dispatchEvent", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[@class='G-Ni J-J5-Ji'][last()]/div[@role='button']", "wait": 5, "sleep": 1},
        {"action": "check_if_exist", "xpath": "//div[@role='menu' and @aria-haspopup='true' and not(contains(@style,'display: none;'))]/div[@class='SK AX']/div[28][@role='menuitem']", "wait": 1, "sleep": 0,
         "sub_action": [
             {"action": "dispatchEventTwo", "xpath": "//div[@role='menu' and @aria-haspopup='true' and not(contains(@style,'display: none;'))]/div[@class='SK AX']/div[28][@role='menuitem']", "wait": 1, "sleep": 1},
             {"action": "dispatchEvent", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[@class='G-Ni J-J5-Ji'][last()]/div[@role='button']", "wait": 5, "sleep": 1},
         ]},
        {"action": "check_if_exist", "xpath": "//div[@role='menu' and @aria-haspopup='true' and not(contains(@style,'display: none;'))]/div[@class='SK AX' ]/div[3][not(@aria-disabled='true')]", "wait": 1, "sleep": 0,
         "sub_action": [
             {"action": "dispatchEventTwo", "xpath": "//div[@role='menu' and @aria-haspopup='true' and not(contains(@style,'display: none;'))]/div[@class='SK AX' ]/div[3][not(@aria-disabled='true')]", "wait": 2, "sleep": 0}
         ]},
        {"action": "check_if_exist", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[@class='G-Ni J-J5-Ji'][last()]/div[@role='button' and @aria-expanded='true']", "wait": 1, "sleep": 0,
         "sub_action": [
             {"action": "dispatchEvent", "xpath": "//div[@gh='mtb']//div[@class='G-tF']/div[@class='G-Ni J-J5-Ji'][last()]/div[@role='button' and @aria-expanded='true']", "wait": 1, "sleep": 0}
         ]}
    ],
    "reply_message": [
        {"action": "click", "xpath": "(//div[@data-message-id])[1]/div[2]/div[1]/table/tbody/tr/td[4]/div[@role='button'][2]", "wait": 5, "sleep": 1 },
        {"action": "send_keys_Reply", "xpath": "//div[@role='textbox']", "value": "reply azedine azedineazedine azedine v azedine  ", "wait": 3, "sleep": 1},
        {"action": "click", "xpath": "//table[@role='group']/tbody/tr/td[1]/div[1]/div[2]/div[@role='button'][1]", "wait": 10, "sleep": 5}
    ],
    "change_password": [
        {"action": "open_url", "url": "https://myaccount.google.com/security", "sleep": 5},
        {"action": "click", "xpath": "//a[contains(@href,'signinoptions/rescuephone')]", "wait": 5, "sleep": 1 },
        {"action": "check_if_exist", "xpath": "//input[@type='password']", "wait": 5, "sleep": 0,
            "sub_action": [
                {"action": "send_keys", "xpath": "//input[@type='password']", "value": __password__, "wait": 5, "sleep": 1},
                {"action": "press_keys", "xpath": "//button[.//span[text()='Suivant']] | //button[.//span[text()='Next']]", "wait": 1, "sleep": 5}
            ]
        },
        {"action": "check_if_exist", "xpath": "(//div[@data-challengeid])[last()]", "wait": 5, "sleep": 0, "sub_action": [
            {"action": "click", "xpath": "(//div[@data-challengeid])[last()]", "wait": 5, "sleep": 1},
            {"action": "send_keys", "xpath": "//input[@id='knowledge-preregistered-email-response']", "value": __recovry__ , "wait": 5, "sleep": 1},
            {"action": "press_keys", "xpath": "//button[.//span[text()='Suivant']] | //button[.//span[text()='Next']]", "wait": 1, "sleep": 5},
        ]},
        {"action": "replace_url_1", "wait": 1, "sleep": 3},
        {"action": "send_keys", "xpath": "(//input[@type='password'])[1]", "value": __newPassword__, "wait": 5, "sleep": 1},
        {"action": "send_keys", "xpath": "(//input[@type='password'])[2]", "value": __newPassword__, "wait": 5, "sleep": 1},
        {"action": "click", "xpath": "//button[@type='submit']", "wait": 5, "sleep": 3},
        {"action": "click", "xpath": "//a[contains(@href,'signinoptions/rescuephone')]", "wait": 5, "sleep": 1}
    ],
    "change_recovery": [
        {"action": "open_url", "url": "https://myaccount.google.com/security", "sleep": 5},
        {"action": "click", "xpath": "//a[contains(@href,'signinoptions/rescuephone')]", "wait": 5, "sleep": 1},
        {"action": "check_if_exist", "xpath": "//input[@type='password']", "wait": 5, "sleep": 0, "sub_action": [
            {"action": "send_keys", "xpath": "//input[@type='password']", "value": "password", "wait": 5, "sleep": 1},
            {"action": "press_keys", "xpath": "//button[.//span[text()='Suivant']] | //button[.//span[text()='Next']]",  "wait": 1, "sleep": 5},
        ]},
        {"action": "check_if_exist", "xpath": "(//div[@data-challengeid])[last()]", "wait": 5, "sleep": 0,"sub_action": [
             {"action": "click", "xpath": "(//div[@data-challengeid])[last()]", "wait": 5, "sleep": 1},
             {"action": "send_keys", "xpath": "//input[@id='knowledge-preregistered-email-response']","value": __recovry__ , "wait": 5, "sleep": 1},
             {"action": "press_keys", "xpath": "//button[.//span[text()='Suivant']] | //button[.//span[text()='Next']]", "wait": 1, "sleep": 5}
         ]},
        {"action": "replace_url_2", "wait": 1, "sleep": 3},
        {"action": "clear", "xpath": "//input[@type='email']", "wait": 5, "sleep": 1},
        {"action": "send_keys", "xpath": "//input[@type='email']", "value": __newRecovry__  , "wait": 5, "sleep": 1},
        {"action": "click", "xpath": "//button[@type='submit']", "wait": 5, "sleep": 3}
    ],
    "add_contacts": [
       {"action": "contact", "wait": 1, "sleep": 3}
    ]
    ,
    "return_back":[
        {"action": "dispatchEvent", "xpath": "//div[@role='button' and (starts-with(@title, 'Retour') or starts-with(@title,'Back') or starts-with(@aria-label, 'Back to') or starts-with(@aria-label, 'Retour'))]", "wait": 5, "sleep": 1 }

    ]
}