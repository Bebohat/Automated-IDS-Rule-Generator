	package bachelor.main.IntrusionRuleGeneration;
	
	
	import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
	import java.util.Random;
	
	
	
	
	public class GeneticAlgorithm {
        public class Rule {
        	int true_Pos;
    		int true_Neg;
    		int false_Pos;
    		int false_Neg;
    		double Precision;
    		double recall;
			String ruleStr;
			String rule_ttl_operator;
			String rule_ttl;
			String rule_stream_size_operator;
			String rule_stream_size;
			String rule_operator;
			String rule_ct_dst_src_ltm;
			int ruleDetec = 0;
			String encoded_rep;
			String rule_attack_name;
			public int ruleDetec_wrong_Normal =0;
			public double f1_score;
			
			public Rule() {
				
			}

			public int getRuleDetec() {
				return ruleDetec;
			}
			public double getF1_Score() {
				return f1_score;
			}
			

			
			
		}
       
		
		int exploits_Attacks = 19689;
		int dos_Attacks = 2281;
		int reconnaissance_Attack = 5100;
		int fuzzers_Attacks = 11761;
				
		int total_Normal = 39121;
        List<Rule> top24Rules = new ArrayList<>();
		List<Rule> rules = new ArrayList<>();
		String ttl_operator;
		String ttl;
		String stream_size_operator;
		String stream_size;
		String operator;
		String ct_dst_src_ltm;
		String attack_name;
		ArrayList<String> population = new ArrayList<>();
		ArrayList<Rule> Parents = new ArrayList<>();
		String [] ttl_operatorsArr = {"<",">","=","<=",">="};
		String [] ttlArr = {"254","62"};
		String [] operatorsArr = {"<",">","="};
		String[] ct_dst_src_ltm_Arr = {
	            "1", "2", "3", "4", "5", "6", "7", "8", "9","10", "11", "12", "13", "19"
	        };
		String [] stream_size_operatorsArr = {"<",">","=","<=",">="};
		 String[] sbytesArr = {
		            "1010", "1002", "1022", "1018", "1014", "1066", "1058", "1068", "1110", "1106",
		            "1162", "1170", "1194", "364", "2516", "2550", "1252", "1264", "1260", "1272",
		            "1268", "1280", "450", "490", "534", "546", "564", "566", "588", "590", "608",
		            "694", "1526", "756", "758", "774", "776", "778", "782", "784", "786", "788",
		            "790", "792", "794", "796", "798", "1612", "800", "802", "804", "806", "808",
		            "810", "812", "814", "816", "818", "820", "822", "824", "826", "828", "830",
		            "832", "834", "836", "838", "840", "842", "844", "846", "848", "850", "852",
		            "854", "856", "858", "860", "862", "866", "870", "872", "874", "876", "878",
		            "888", "900", "910", "912", "922", "948", "950", "954", "956", "986", "994",
		            "998"
		        };
		
		 
		String [] attack_labels = {"Exploits","Fuzzers","Reconnaissance","DoS"};
		
		ArrayList<attack> attacksList = new ArrayList<>();
		
	
		
	
			
			//alert tcp any any -> any any ( ttl:254; flow:to_server,established; flowbits:set,conn_count; flowbits:isnotset,conn_limit; count conn_count > 100, 4; stream_size:=125,to_server;
			//msg:"Custom rule: Conditions met"; sid:1004;)
	
			//ttl:<32;  to detect packets with a TTL less than 32:
			//flow:to_server,established; flowbits:set,conn_count; flowbits:isnotset,conn_limit; count conn_count > 100, 4;
			//Number of Connections of the Same Source and Destination in 100 Connections According to the Last Time = 4:
			
			
			
			
			
		
		public GeneticAlgorithm() {
			
		}
        
	
		
		 private static final int POPULATION_SIZE = 50;
		    private static final double MUTATION_RATE = 0.3;
		    private static final int MAX_GENERATIONS = 1000;
		    
		    
		   // private static final String TOURNAMENT_SIZE = 5;
	
		 
		    // Initialize the population
		    private void Populate() {
		    	
		    	int i =0;
		    	while(i<500) {
		    	Random random = new Random();
		    	int one_digit_ttl_operators = random.nextInt(5);
		    	int one_digit_ttl = random.nextInt(2);
		    	int one_digit_operator = random.nextInt(3);
		    	int two_digit_ct_dst_src_ltm = random.nextInt(14);
		    	int one_digit_stream_size_operators = random.nextInt(5);
		    	int two_digit_stream_size = random.nextInt(91);
		    	int one_digit_attack_name = random.nextInt(4);
		    	
		    	
		    	
		    	if(Integer.toString(two_digit_stream_size).length()<2&& Integer.toString(two_digit_ct_dst_src_ltm).length()<2) {
		    		String s = "0"+Integer.toString(two_digit_stream_size);
		    		String s1 = "0"+Integer.toString(two_digit_ct_dst_src_ltm);
		    		
		    		String result = Integer.toString(one_digit_ttl_operators) + Integer.toString(one_digit_ttl) +Integer.toString(one_digit_operator) 
		    		+ s1 + Integer.toString(one_digit_stream_size_operators)+  s+ Integer.toString(one_digit_attack_name);
		    		population.add(result);
		    	}
		    	else if (Integer.toString(two_digit_stream_size).length()<2&& Integer.toString(two_digit_ct_dst_src_ltm).length()==2) {
		    		String s = "0"+Integer.toString(two_digit_stream_size);
		    		
		    		
		    		String result = Integer.toString(one_digit_ttl_operators) + Integer.toString(one_digit_ttl) +Integer.toString(one_digit_operator) 
		    		+ Integer.toString(two_digit_ct_dst_src_ltm) + Integer.toString(one_digit_stream_size_operators)+  s +Integer.toString(one_digit_attack_name);
		    		population.add(result);
		    	}
		    	else if(Integer.toString(two_digit_stream_size).length()==2&& Integer.toString(two_digit_ct_dst_src_ltm).length()<2) {
		    		String s1 = "0"+Integer.toString(two_digit_ct_dst_src_ltm);
		    		
		    		String result = Integer.toString(one_digit_ttl_operators) + Integer.toString(one_digit_ttl) +Integer.toString(one_digit_operator) 
		    		+ s1 + Integer.toString(one_digit_stream_size_operators)+Integer.toString(two_digit_stream_size)+Integer.toString(one_digit_attack_name);
		    		population.add(result);
		    	}
		    	else {
		    		String result = Integer.toString(one_digit_ttl_operators) + Integer.toString(one_digit_ttl)+Integer.toString(one_digit_operator)
		    		+ Integer.toString(two_digit_ct_dst_src_ltm)+ Integer.toString(one_digit_stream_size_operators) +  Integer.toString(two_digit_stream_size)+Integer.toString(one_digit_attack_name);
		    		population.add(result);
		    	}
		   
		    	
		    	i++;
		    	}
		    	
		        
		    }
		    
		    public void transelateToRule(String encoded) {
		    	
		    	for(int i = 0 ; i< encoded.length();i++) {
		    	    if(i==0) {
		    	    	
		    	        ttl_operator = ttl_operatorsArr[Character.getNumericValue(encoded.charAt(i))];
		    	      
		    	    }
		    	    else if (i==1) {
		    	        ttl = ttlArr[Character.getNumericValue(encoded.charAt(i))];
		    	       
		    	    }
		    	    else if(i==2) {
		    	    	operator =  operatorsArr[Character.getNumericValue(encoded.charAt(i))];
		    	    }
		    	    else if (i==3) { 
		    	    	 StringBuilder sb = new StringBuilder();
			    	        sb.append(encoded.charAt(i));
			    	        sb.append(encoded.charAt(i+1));  
			    	        ct_dst_src_ltm = ct_dst_src_ltm_Arr[Integer.parseInt(sb.toString())];
			    	        i++;
		    	    	
		    	    }
		    	    else if (i==5) {
		    	    	stream_size_operator = stream_size_operatorsArr[Character.getNumericValue(encoded.charAt(i))];
		    	    }                           
		    	    else if (i==6) {
		    	    	 StringBuilder sb = new StringBuilder();
			    	        sb.append(encoded.charAt(i));
			    	        sb.append(encoded.charAt(i+1));  
			    	        stream_size =  sbytesArr[Integer.parseInt(sb.toString())];
			    	        i++;
		    	    }
		    	    else if(i==8) {
		    	    	attack_name = attack_labels[Character.getNumericValue(encoded.charAt(i))];
		    	    }
		    	    
		    	}
		    	Rule rule = new Rule();
		    	rule.encoded_rep = encoded;
		    	rule.rule_ttl_operator = ttl_operator;
		    	rule.rule_ttl = ttl;
		    	rule.rule_operator = operator;
		    	rule.rule_ct_dst_src_ltm = ct_dst_src_ltm;
		    	rule.rule_stream_size_operator = stream_size_operator;
		    	rule.rule_stream_size = stream_size;
		    	rule.rule_attack_name = attack_name;
		    	 rule.ruleStr = "alert tcp any any -> any any" +  "("+" ttl:" + ttl_operator + ttl +";"+"flow:to_server,established; flowbits:set,conn_count; flowbits:isnotset,conn_limit; count conn_count"+ operator + ct_dst_src_ltm+ ",4;"
		    	        +"stream_size:"+ stream_size_operator+ stream_size+","+"to_server;"+ "msg:Custom rule:" + attack_name + " Detected;);";
		    	 if (rules.stream().noneMatch(r -> r.ruleStr.equals(rule.ruleStr))) {
		    		    rules.add(rule);
		    		}
	
		    																	
		    }
	
		    // Evaluate the fitness of each individual in the population
		    private void evaluatePopulation() {
		    	 attack att = new attack();
		    	 att.loadAttacksFromCSV();
		    	
		    	 for(Rule rule : rules) {
		    		 rule.ruleDetec = 0;
		    		 rule.true_Pos = 0;
		    		 rule.true_Neg = 0;
		    		 rule.false_Pos = 0;
		    		 rule.false_Neg = 0;
		    		 rule.Precision = 0;
		    		 rule.recall = 0;
		    		 rule.f1_score = 0;
		    	 }
		    	 for(Rule rule : rules) {
		    		 for(attack a : att.getAttacksList()) {
		    			 boolean ttl_flag = false;
		 		    	boolean ct_dst_src_ltm_flag =false ;
		 		    	boolean stream_size_flag = false;
		 		    	boolean attack_name_flag = false;
			    		 if(rule.rule_ttl_operator .equals("<")) {
			    			 if(Integer.parseInt(a.sttl) < Integer.parseInt(rule.rule_ttl)) {
			    				 //System.out.println(a.sttl + "<"+ rule.rule_ttl);
			    				 ttl_flag =true;
			    			 }
			    		 }
						if(rule.rule_ttl_operator .equals(">")) {
							 if(Integer.parseInt(a.sttl) > Integer.parseInt(rule.rule_ttl)) {
								// System.out.println(a.sttl + ">"+ rule.rule_ttl);
								
			    				 ttl_flag =true;
			    			 }    			 
									    		 }
						
						if(rule.rule_ttl_operator .equals("=")) {
							 if(Integer.parseInt(a.sttl) == Integer.parseInt(rule.rule_ttl)) {
								// System.out.println(a.sttl + "=="+ rule.rule_ttl);
			    				 ttl_flag =true;
			    			 }
							 
						}
						if(rule.rule_ttl_operator .equals("<=")) {
							 if(Integer.parseInt(a.sttl) <= Integer.parseInt(rule.rule_ttl)) {
							//	 System.out.println(a.sttl + "<="+ rule.rule_ttl);
			    				 ttl_flag =true;
			    			 }
							 
						}
						if(rule.rule_ttl_operator .equals(">=")) {
							 if(Integer.parseInt(a.sttl) >= Integer.parseInt(rule.rule_ttl)) {
							//	 System.out.println(a.sttl + ">="+ rule.rule_ttl);
			    				 ttl_flag =true;
			    			 }
						}
						if(rule.rule_operator .equals("<")) {
			    			 if( Integer.parseInt(a.ct_dst_src_ltm) < Integer.parseInt(rule.rule_ct_dst_src_ltm)) {
			    			//	 System.out.println(a.ct_dst_src_ltm + "<"+ rule.rule_ct_dst_src_ltm);
			    				 ct_dst_src_ltm_flag = true;
			    			 }
			    		 }
						if(rule.rule_operator .equals(">")) {
							if(Integer.parseInt(a.ct_dst_src_ltm) > Integer.parseInt(rule.rule_ct_dst_src_ltm)) {
							//	System.out.println(a.ct_dst_src_ltm + ">"+ rule.rule_ct_dst_src_ltm);
			    				 ct_dst_src_ltm_flag = true;
			    			 }  			 
						}
						if(rule.rule_operator .equals("!")) {
							if(Integer.parseInt(a.ct_dst_src_ltm) != Integer.parseInt(rule.rule_ct_dst_src_ltm)) {
							//	System.out.println(a.ct_dst_src_ltm + "!="+ rule.rule_ct_dst_src_ltm);
			    				 ct_dst_src_ltm_flag = true;
			    			 }  			 
						}
						if(rule.rule_operator .equals("=")) {
							if(Integer.parseInt(a.ct_dst_src_ltm) == Integer.parseInt(rule.rule_ct_dst_src_ltm)) {
							//	System.out.println(a.ct_dst_src_ltm + "=="+ rule.rule_ct_dst_src_ltm);
			    				 ct_dst_src_ltm_flag = true;
			    			 }  			 
						}
						if(rule.rule_operator .equals("<=")) {
							if(Integer.parseInt(a.ct_dst_src_ltm) <= Integer.parseInt(rule.rule_ct_dst_src_ltm)) {
							//	System.out.println(a.ct_dst_src_ltm + "<="+ rule.rule_ct_dst_src_ltm);
			    				 ct_dst_src_ltm_flag = true;
			    			 }  			 
						}
						if(rule.rule_operator .equals(">=")) {
							if(Integer.parseInt(a.ct_dst_src_ltm) >= Integer.parseInt(rule.rule_ct_dst_src_ltm)) {
						//		System.out.println(a.ct_dst_src_ltm + ">="+ rule.rule_ct_dst_src_ltm);
			    				 ct_dst_src_ltm_flag = true;
			    			 }  			 
						}
						if(rule.rule_stream_size_operator.equals("<")) {
							if(Integer.parseInt(a.sbytes)<Integer.parseInt(rule.rule_stream_size)) {
					//			System.out.println(a.sbytes + "<"+ rule.rule_stream_size);
			    				 stream_size_flag = true;
			    			 }  			 
						}
						if(rule.rule_stream_size_operator.equals(">")) {
							if(Integer.parseInt(a.sbytes)>Integer.parseInt(rule.rule_stream_size)) {
						//		System.out.println(a.ct_dst_src_ltm + ">"+ rule.rule_ct_dst_src_ltm);
			    				 stream_size_flag = true;
			    			 }  			 
						}
						if(rule.rule_stream_size_operator.equals("!")) {
							if(Integer.parseInt(a.sbytes) != Integer.parseInt(rule.rule_stream_size)) {
						//		System.out.println(a.ct_dst_src_ltm + "!="+ rule.rule_ct_dst_src_ltm);
			    				 stream_size_flag = true;
			    			 }  			 
						}
						if(rule.rule_stream_size_operator.equals("=")) {
							if(Integer.parseInt(a.sbytes) == Integer.parseInt(rule.rule_stream_size)) {
						//		System.out.println(a.ct_dst_src_ltm + "=="+ rule.rule_ct_dst_src_ltm);
			    				 stream_size_flag = true;
			    			 }  			 
						}
						if(rule.rule_stream_size_operator.equals("<=")) {
							if(Integer.parseInt(a.sbytes)<=Integer.parseInt(rule.rule_stream_size)) {
							//	System.out.println(a.ct_dst_src_ltm + "<="+ rule.rule_ct_dst_src_ltm);
			    				 stream_size_flag = true;
			    			 }  			 
						}
						if(rule.rule_stream_size_operator.equals(">=")) {
							if(Integer.parseInt(a.sbytes)>=Integer.parseInt(rule.rule_stream_size)) {
							//	System.out.println(a.ct_dst_src_ltm + ">="+ rule.rule_ct_dst_src_ltm);
			    				 stream_size_flag = true;
			    			 }  			 
						}
						if(rule.rule_attack_name.equals(a.attack_cat)) {
							attack_name_flag = true;
						}
						if(stream_size_flag==true && ct_dst_src_ltm_flag == true && ttl_flag ==true && attack_name_flag == true) {
							rule.ruleDetec++;
							rule.true_Pos++;
							
							
						}
						if(stream_size_flag==true && ct_dst_src_ltm_flag == true && ttl_flag ==true && a.attack_cat.equals("Normal")) {
								rule.false_Pos++;
								rule.true_Neg = total_Normal - rule.false_Pos ;
						}
						
							
							
					}
		    		 int x = rule.true_Pos + rule.false_Pos;
		    		 if (x > 0) {
		    		     rule.Precision = (double) rule.true_Pos / x;
		    		 } else {
		    		     rule.Precision = 0.0; // Handle the case where true_Pos and false_Pos are both zero
		    		 }
		    		 
		    		 if(rule.rule_attack_name.equals("Exploits")) {
							rule.false_Neg = exploits_Attacks-rule.true_Pos;
						}
						if(rule.rule_attack_name.equals("Fuzzers")) {
							rule.false_Neg = fuzzers_Attacks-rule.true_Pos;
						}
						if(rule.rule_attack_name.equals("DoS")) {
							rule.false_Neg = dos_Attacks-rule.true_Pos;
						}
						if(rule.rule_attack_name.equals("Reconnaissance")) {
							rule.false_Neg = reconnaissance_Attack-rule.true_Pos;
						}
		    		 
		    		 
		    		 int x1 = rule.true_Pos + rule.false_Neg;
		    		if(x1>0) {
		    			
				    		rule.recall = (double)rule.true_Pos / x1;
				    		
		    		 }
		    		double x2 = rule.Precision + rule.recall;
		    		if(x2>0) {
		    			rule.f1_score = (double) (2*rule. Precision*rule.recall / x2); 
		    		}
		    		    
			    		
		    		 } 
		    	}
		    	 
		    
	
		    // Select parents using tournament selection
//		    private void selectParent() {
//		    	Random random = new Random();
//		        
//		    	Collections.sort(rules,Comparator.comparingInt(Rule::getRuleDetec).reversed());
//		    	
////		        rules =  rules.subList(0, Math.min(126, rules.size()));
//		        
//		        	int i = 0;
//		        	while(i<124) {
//		        	Rule parent1 = rules.get(random.nextInt(rules.size()));
//		            Rule parent2 = rules.get(random.nextInt(rules.size()));
//		            String child = crossover(parent1, parent2);
//		            String mutated_child = mutate(child);
//		            transelateToRule(mutated_child);
//		            i++;
//		            
//		            
//		        	}
//		       
//		        
//		    }
//	
		    private void selectParent() {
		       
		    	Random random = new Random();
		        List<Rule> bestReconnaissanceRules = new ArrayList<>();
		        List<Rule> bestExploitsRules = new ArrayList<>();
		        List<Rule> bestDoSRules = new ArrayList<>();
		        List<Rule> bestFuzzersRules = new ArrayList<>();

		        Collections.sort(rules, Comparator.comparingDouble(Rule::getF1_Score).reversed());

		        for (Rule rule : rules) {
		           
		            if (bestReconnaissanceRules.size() >= 20 && bestExploitsRules.size() >= 24 &&
		                bestDoSRules.size() >= 42 && bestFuzzersRules.size() >= 24) {
		                break; 
		            }

		          
		            if (rule.rule_attack_name.equals("Reconnaissance") && bestReconnaissanceRules.size() < 20) {
		                bestReconnaissanceRules.add(rule);
		            } else if (rule.rule_attack_name.equals("Exploits") && bestExploitsRules.size() < 24) {
		                bestExploitsRules.add(rule);
		            } else if (rule.rule_attack_name.equals("DoS") && bestDoSRules.size() < 42) {
		                bestDoSRules.add(rule);
		            } else if (rule.rule_attack_name.equals("Fuzzers") && bestFuzzersRules.size() < 24) {
		                bestFuzzersRules.add(rule);
		            }
		        }
		        rules.clear();
		        rules.addAll(bestReconnaissanceRules);
		        rules.addAll(bestExploitsRules);
		        rules.addAll(bestDoSRules);
		        rules.addAll(bestFuzzersRules);
		        int i = 0;
	        	while(i<110) {
	        	Rule parent1 = rules.get(random.nextInt(rules.size()));
	            Rule parent2 = rules.get(random.nextInt(rules.size()));
	            String child = crossover(parent1, parent2);
	            String mutated_child = mutate(child);
	            transelateToRule(mutated_child);
	            i++;
	            
	            }

		        // Now, you have the best 36 rules for each attack in their respective lists
		    }



	
		    // Crossover two parents to produce offspring
		    public String crossover(Rule parent1, Rule parent2) {
		        Random random = new Random();
		        int crossoverPoint = random.nextInt(parent1.encoded_rep.length());
		        if(crossoverPoint == 7 ) {
		        	crossoverPoint = 6;
		        }
		        if( crossoverPoint == 4 ) {
		        	crossoverPoint = 3;
		        }
		        int rand =random.nextInt(2);
		        String offspring1 = parent1.encoded_rep.substring(0, crossoverPoint) + parent2.encoded_rep.substring(crossoverPoint);
		        String offspring = parent2.encoded_rep.substring(0, crossoverPoint) + parent1.encoded_rep.substring(crossoverPoint);
		        if(rand==0) {
		        	return offspring;
		        }else {
		        return offspring1;
		        }
		    }
	
		    public String mutate(String offspring) {
		        // Implement mutation logic here
		        Random random = new Random();
		        StringBuilder mutatedOffspring = new StringBuilder();

		        for (int i = 0; i < offspring.length(); i++) {
		            char gene = offspring.charAt(i);
		            
		            // Check if mutation should be applied based on mutation rate
		            if (random.nextDouble() < MUTATION_RATE) {
		                char mutatedGene;
		                
		                // Apply mutation based on the position in the offspring string
		                switch (i) {
		                    case 0: // Mutate ttl_operators
		                        int one_digit_ttl_operators = random.nextInt(5);
		                        mutatedGene = Character.forDigit(one_digit_ttl_operators, 10);
		                        break;
		                    case 1: // Mutate ttl
		                        int one_digit_ttl = random.nextInt(2);
		                        mutatedGene = Character.forDigit(one_digit_ttl, 10);
		                        break;
		                    case 2: // Mutate operator
		                    	int one_digit_operator =  random.nextInt(3);
		                    	mutatedGene = Character.forDigit(one_digit_operator, 10);
		                        mutatedGene = gene;
		                        break;
		                    case 3: // Mutate ct_dst_src_ltm
		                    	int two_digit_ct_dst_src_ltm = random.nextInt(14);
		                    	mutatedGene = Character.forDigit(two_digit_ct_dst_src_ltm, 100);
		                        mutatedGene = gene; 
		                        break;
		                    case 4: // Mutate stream_size_operators
		                    	int one_digit_stream_size_operators = random.nextInt(5);
		                    	mutatedGene = Character.forDigit(one_digit_stream_size_operators, 10);
		                        mutatedGene = gene; 
		                        break;
		                    case 5: // Mutate stream_size
		                    	int two_digit_stream_size = random.nextInt(91);
		                    	mutatedGene = Character.forDigit(two_digit_stream_size, 100);
		                        mutatedGene = gene; 
		                        break;
		                    default:
		                        mutatedGene = gene; // Keep unchanged for unrecognized positions
		                }
		                
		                mutatedOffspring.append(mutatedGene);
		            } else {
		                mutatedOffspring.append(gene); // Keep unchanged if no mutation
		            }
		        }

		        return mutatedOffspring.toString();
		    }

	
		    
		    
		    
		   
		    
		    public static void main(String[] args) {
		       
		    	GeneticAlgorithm GA = new GeneticAlgorithm();
		    	GA.Populate();
	            for(String s : GA.population) {
	            	GA.transelateToRule(s);
	            }
	            GA.evaluatePopulation();
	            GA.selectParent();
	            boolean Reconnaissance_met = false;
	            boolean Exploits_met = false;
	            boolean DoS_met =false;
	            boolean fuzzers_met = false;
		    	boolean conditionMet=false;
				while (!conditionMet) {
		            for (Rule rule : GA.rules) {
		                //if (rule.ruleDetec >= 17900 && rule.rule_attack_name.equals("Exploits")&&rule.f1_score>0.8) 

		            		if(rule.rule_attack_name.equals("Exploits")&&rule.f1_score>0.85) {
		                    Exploits_met = true;
		                    System.out.println(rule.ruleStr + rule.ruleDetec + " True_pos " + rule.true_Pos + " False_Pos " + rule.false_Pos +  "  Precission:" + rule.Precision + " recall:"+rule.recall + " f1 score:"  + rule.f1_score);	
		                    //break; // Exit the loop once the condition is met
		                }
		               // if (rule.ruleDetec >= 4800 && rule.rule_attack_name.equals("Reconnaissance")&&rule.f1_score>0.8) {
		                	 if ( rule.rule_attack_name.equals("Reconnaissance")&&rule.f1_score>0.85) {
		                	Reconnaissance_met = true;
		                	System.out.println(rule.ruleStr + rule.ruleDetec + " True_pos " + rule.true_Pos + " False_Pos " + rule.false_Pos +  "  Precission:" + rule.Precision + " recall:"+rule.recall + " f1 score:"  + rule.f1_score);	
		                }
		                if (rule.ruleDetec >= 2050 && rule.rule_attack_name.equals("DoS")) {
		                	DoS_met = true;
		                	//System.out.println(rule.ruleStr+rule.ruleDetec);
		                }
		               // if (rule.ruleDetec >= 10850 && rule.rule_attack_name.equals("Fuzzers")&&rule.f1_score>0.8) {
		                if (rule.rule_attack_name.equals("Fuzzers")&&rule.f1_score>0.74) {
		                	fuzzers_met = true;
		                	System.out.println(rule.ruleStr + rule.ruleDetec + " True_pos " + rule.true_Pos + " False_Pos " + rule.false_Pos +  "  Precission:" + rule.Precision + " recall:"+rule.recall + " f1 score:"  + rule.f1_score);	
		                }
		                if(Reconnaissance_met == true && Exploits_met == true && DoS_met == true && fuzzers_met == true) {
		                	conditionMet = true;
		                }
		                      
		            }
		            GA.evaluatePopulation();
		            GA.selectParent();
		            
		        }
				
				System.out.println("---------------------------------------------------------------------------------------------------------------------------------");
				for(Rule rule : GA.rules) {
					System.out.println(rule.ruleStr + rule.ruleDetec + " True_pos " + rule.true_Pos + " False_Pos " + rule.false_Pos +  "  Precission:" + rule.Precision + " recall:"+rule.recall + " f1 score:"  + rule.f1_score);	
				}
				
				
				 
		    
		            // Example usage of Genetic Algorithm
//		            GeneticAlgorithm geneticAlgorithm = new GeneticAlgorithm();
//		            geneticAlgorithm.Populate();
//		            for(String s : geneticAlgorithm.population) {
//		            	geneticAlgorithm.transelateToRule(s);
//		            }
//		          
//		           
//	               geneticAlgorithm.evaluatePopulation();
////		            for(Rule rule : geneticAlgorithm.rules) {
////		            	System.out.println(rule.ruleStr +"detected"+":" + rule.ruleDetec);
////		            }
////		            System.out.println("----------------------------------------------------------------------------------------------------------------------------------");
//		            geneticAlgorithm.selectParent();
////		            for(Rule rule : geneticAlgorithm.rules) {
////		            	System.out.println(rule.ruleStr+"detected"+":" + rule.ruleDetec);
////		            }
////		            System.out.println("----------------------------------------------------------------------------------------------------------------------------------");
//		            geneticAlgorithm.evaluatePopulation();
//		            Collections.sort(geneticAlgorithm.rules,Comparator.comparingInt(Rule::getRuleDetec).reversed());
//		            for(Rule rule : geneticAlgorithm.rules) {
//		            	System.out.println(rule.ruleStr+"detected"+":" + rule.ruleDetec);
//		            }
		            
		            
		           
		            
//		            String a = geneticAlgorithm.population.get(0);
//		            String b = geneticAlgorithm.population.get(1);
//		            System.out.println(a);
//		            System.out.println(b);
//		           String c = geneticAlgorithm.crossover(a, b);
//		           System.out.println(c);
//		            System.out.println(geneticAlgorithm.mutate(a));
//		            System.out.println(geneticAlgorithm.rules.get(23));
		            
		            
	
	
		    }
		}
		
	
		
		
	
