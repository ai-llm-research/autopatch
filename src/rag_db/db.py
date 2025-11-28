from sqlalchemy import create_engine, Engine
from sqlalchemy.sql import text
from langchain_openai import OpenAIEmbeddings
from sklearn.metrics.pairwise import cosine_similarity
from langchain.schema import BaseRetriever
from typing import List, Optional
from langchain.schema import Document
import spacy
from dataclasses import dataclass
import textwrap
import json
import pandas as pd
import os
from rapidfuzz import process, fuzz

# PostgreSQL connection INFO
DB_USER = "autopatch"
DB_PASSWORD = "autopatch!1234"
DB_NAME = "autopatch_db"
DB_HOST = "localhost"
DB_PORT = "5432"
TAG_CSV = os.path.dirname(os.path.abspath(__file__)) +"/programming_tags.csv" #PATH_TO_TAGS_CSV
FUZZ_THRESHOLD = 80

@dataclass
class RAGDataEntry:
    id : int
    cwe_type: str
    cve_id: str
    supplementary_code: str
    original_code: str
    vuln_patch: str
    function_name: str
    function_prototype: str
    code_semantics: dict # {"raw": string, "vec": vector list, "ner": ner list}
    verification_cot: str
    safe_verification_cot: str
    vulnerability_checklist: str
    vulnerability_related_variables: dict # {"variable_name": {"raw": string, "vec": vector list}, ...}
    vulnerability_related_functions: dict # {"function_name": {"raw": string, "vec": vector list}, ...}
    root_cause: str
    patch_cot: str
    fix_list: str


    def schema():
        # Need to maintain the order according to that of the RAGDataEntry varaibles
        # cwe_type TEXT: cwe type
        # cve_id TEXT: cve id
        # supplementary_code TEXT
        # original_code TEXT: vulnerable code of CVE-xxx-xxx
        # vuln_patch TEXT: patched code of CVE-xxx-xxx
        # function_name TEXT: function name of vulnerable code
        # function_prototype TEXT: function prototype of vulnerable code
        # code_semantics TEXT: code semantics of the vulnerable code of CVE-xxx-xxx (code_semantics.txt)
        # verification_cot: verifcation cot (verify_cot_generation.txt)
        # vulnerability_related_variables: verification-related important variables' role summary list (verify_cot_generation.txt & variable_summary.txt) => ```json````
        # vulnerability_related_functions: verification-related important functions' role summary list (verify_cot_generation.txt & function_summary.txt) => ```json````
        # root_cause TEXT: vulnerability root-cause
        # patch_cot: patch cot (patch_cot_generation.txt)
        return textwrap.dedent(
            """
            id SERIAL PRIMARY KEY,
            cwe_type TEXT, 
            cve_id TEXT,
            supplementary_code TEXT,
            original_code TEXT, 
            vuln_patch TEXT, 
            function_name TEXT, 
            function_prototype TEXT, 
            code_semantics TEXT,
            verification_cot TEXT,
            safe_verification_cot TEXT,
            vulnerability_checklist TEXT,
            vulnerability_related_variables TEXT,
            vulnerability_related_functions TEXT,
            root_cause TEXT,
            patch_cot TEXT,
            fix_list TEXT
            """
        ) # dedent end

    def from_db(row):
        data_args = {}
        data_args['id'] = row['id']
        data_args['cwe_type'] = row['cwe_type']
        data_args['cve_id'] = row['cve_id']
        data_args['supplementary_code'] = row['supplementary_code']
        data_args['original_code'] = row['original_code']
        data_args['vuln_patch'] = row['vuln_patch']
        data_args['function_name'] = row['function_name']
        data_args['function_prototype'] = row['function_prototype']
        data_args['code_semantics'] = json.loads(row['code_semantics'])
        data_args['verification_cot'] = row['verification_cot']
        data_args['safe_verification_cot'] = row['safe_verification_cot']
        data_args['vulnerability_checklist'] = row['vulnerability_checklist']
        data_args['vulnerability_related_variables'] = json.loads(row['vulnerability_related_variables'])
        data_args['vulnerability_related_functions'] = json.loads(row['vulnerability_related_functions'])
        data_args['root_cause'] = row['root_cause']
        data_args['patch_cot'] = row['patch_cot']
        data_args['fix_list'] = row['fix_list']
        return RAGDataEntry(**data_args)

    def to_db(self):
        return textwrap.dedent(
            """
            INSERT INTO vulnerabilities 
            (
                cwe_type,
                cve_id,
                supplementary_code,
                original_code,
                vuln_patch,
                function_name,
                function_prototype,
                code_semantics,
                verification_cot,
                safe_verification_cot,
                vulnerability_checklist,
                vulnerability_related_variables,
                vulnerability_related_functions,
                root_cause,
                patch_cot,
                fix_list
            )
            VALUES
            (
                :cwe_type,
                :cve_id,
                :supplementary_code,
                :original_code,
                :vuln_patch,
                :function_name,
                :function_prototype,
                :code_semantics,
                :verification_cot,
                :safe_verification_cot,
                :vulnerability_checklist,
                :vulnerability_related_variables,
                :vulnerability_related_functions,
                :root_cause,
                :patch_cot,
                :fix_list
            )
            ON CONFLICT DO NOTHING;
            """
        ), {
                "cwe_type" : self.cwe_type,
                "cve_id" : self.cve_id,
                "supplementary_code" : self.supplementary_code,
                "original_code" : self.original_code,
                "vuln_patch" : self.vuln_patch,
                "function_name" : self.function_name,
                "function_prototype" : self.function_prototype,
                "code_semantics" : json.dumps(self.code_semantics),
                "verification_cot" : self.verification_cot,
                "safe_verification_cot" : self.safe_verification_cot,
                "vulnerability_checklist" : self.vulnerability_checklist,
                "vulnerability_related_variables" : json.dumps(self.vulnerability_related_variables),
                "vulnerability_related_functions" : json.dumps(self.vulnerability_related_functions),
                "root_cause" : self.root_cause,
                "patch_cot" : self.patch_cot,
                "fix_list" : self.fix_list
         } # dedent end
    
    def calc_vec(self, db):
        self.code_semantics =  {
            "raw": self.code_semantics,
            "vec": db.embeddings.embed_query(self.code_semantics),
            "ner": list(db.extract_keywords(self.code_semantics))
        }

        for key in self.vulnerability_related_variables.keys():
            self.vulnerability_related_variables[key] =  {
                "raw": self.vulnerability_related_variables[key],
                "vec": db.embeddings.embed_query(self.vulnerability_related_variables[key])
            }

        for key in self.vulnerability_related_functions.keys():
            self.vulnerability_related_functions[key] =  {
                "raw": self.vulnerability_related_functions[key],
                "vec": db.embeddings.embed_query(self.vulnerability_related_functions[key])
            }

    def trim_vec(self):
        self.code_semantics.pop("vec", None)

        for key in self.vulnerability_related_variables.keys():
            self.vulnerability_related_variables[key].pop("vec", None)

        for key in self.vulnerability_related_functions.keys():
            self.vulnerability_related_functions[key].pop("vec", None)


class AutoPatchDBWrapper(BaseRetriever):
    def __init__(self, db):
        super().__init__()
        self.__dict__["db"] = db
    
    def _get_relevant_documents(self, query: str):
        match_ids = self.db.search(query)
        match_rag_entries = self.db.get(match_ids)

        result = []
        for vuln_data in match_rag_entries:
            result.append(vuln_data.to_doc())

        return result

class AutoPatchDB:

    def __init__(self, api_key):
        # Create engine
        self.engine = create_engine(f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}")

        # Load spacy NER model
        self.nlp = spacy.load("en_core_web_sm")

        if api_key == "": # For DB initialization
            self.embeddings = None
        else:
            self.embeddings = OpenAIEmbeddings(openai_api_key=api_key)
            self.load()
            self.programming_terms = pd.read_csv(TAG_CSV)["TagName"].str.lower().tolist()

    # Create vulnerabilities table
    def create_table(self):
        with self.engine.begin() as conn:
            conn.execute(
                text("DROP TABLE IF EXISTS vulnerabilities;")
            )

            conn.execute(
                text("CREATE TABLE vulnerabilities ({});".format(RAGDataEntry.schema())
                )
            )
        print("Table Created Successfully!")


    # Clear vulnerabilities table
    def clear_table(self):
        with self.engine.begin() as conn:
            conn.execute(text("DELETE FROM vulnerabilities"))
        print("All existing vulnerabilities data have been removed.")


    # Insert data to vulnerabilities table
    def insert_data(self, rag_data_entry : RAGDataEntry):
        rag_data_entry.calc_vec(self)

        db_query_template, db_query_value = rag_data_entry.to_db()
        with self.engine.begin() as conn:
            conn.execute(text(db_query_template), db_query_value)

    def load(self):
        self.rag_entries = {}
        with self.engine.connect() as conn:
            result = conn.execute(text("SELECT * FROM vulnerabilities"))
            rows = result.mappings().all()
        
        for row in rows:
            rag_data_entry = RAGDataEntry.from_db(row)
            self.rag_entries[rag_data_entry.id] = rag_data_entry


    # Reduce a set of words by merging similar words using RapidFuzz.
    def reduce_set_fuzz(self, word_set):
        reduced_set = set()
        word_list = list(word_set)

        while word_list:
            base_word = word_list.pop(0)
            similar_words = process.extract(base_word, word_list, scorer=fuzz.ratio, score_cutoff=FUZZ_THRESHOLD)
            
            # Remove matched words from the list
            for match, score, _ in similar_words:
                word_list.remove(match)

            reduced_set.add(base_word)  # Keep only one representative word

        return reduced_set


    # Compute the fuzzy intersection between two sets.
    # Two words are considered equal if their similarity exceeds the given threshold.  
    def intersection_fuzz(self, set1, set2):
        matched = set()
        for word1 in set1:
            for word2 in set2:
                if fuzz.ratio(word1, word2) >= FUZZ_THRESHOLD:  # If words are similar enough, count them as the same
                    matched.add(word1)  # We use word1, but it doesn't matter since we're just counting
        
        return len(matched)

    # Jaccard Similarity with rapid fuzz
    def compute_jaccard_similarity_fuzz(self, set1, set2):

        # Reduce sets using fuzzy clustering
        reduced_set1 = self.reduce_set_fuzz(set1)
        reduced_set2 = self.reduce_set_fuzz(set2)

        # Compute fuzzy intersection size
        intersection_size = self.intersection_fuzz(reduced_set1, reduced_set2)

        # Compute union size
        union_size = len(reduced_set1) + len(reduced_set2) - intersection_size

        return intersection_size / union_size if union_size != 0 else 0

    # Jaccard Similarity
    def compute_jaccard_similarity(self, set1, set2):
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union != 0 else 0

    # Cosine Similarity
    def compute_cosine_similarity(self, emb1, emb2):
        return cosine_similarity([emb1], [emb2])[0][0]

    # Extract programming keywords
    def extract_keywords(self,text):
        doc = self.nlp(text)
        nouns = [token.text.lower() for token in doc if token.pos_ == "NOUN"]
        verbs = [token.text.lower() for token in doc if token.pos_ == "VERB"]
        noun_verb_set = set(nouns + verbs)

        programming_noun_verb_list = []
        for word in noun_verb_set:
            best_match = process.extractOne(word, self.programming_terms, scorer=fuzz.ratio)
            if best_match and best_match[1] > 80: # threshold = 80
                programming_noun_verb_list.append(best_match[0])

        return set(programming_noun_verb_list)


    # Map vuln/func name between rag entry and user entry
    def find_var_func_mapping(self, user_list: dict, rag_list: dict):
        mapping = {}
        for rag_entry_name, rag_entry_data in rag_list.items():
            max_cosine_score = 0.0
            max_user_entry_name = None
            for user_entry_name, user_entry_data in user_list.items():
                cosine_score = self.compute_cosine_similarity(rag_entry_data["vec"], user_entry_data["vec"])
                if cosine_score > max_cosine_score:
                    max_cosine_score = cosine_score
                    max_user_entry_name = user_entry_name
            
            if max_cosine_score > 0.5:  # Threshold for similarity
                mapping[rag_entry_name] = {"score":max_cosine_score, "mapped_name": max_user_entry_name}
        
        return mapping


    # Search for the matching rag entry
    def search(self,  user_code_semantics: str, user_code_variables: dict, user_code_functions: dict):
        user_code_semantics_keywords = self.extract_keywords(user_code_semantics)
        user_code_semantics_emded = self.embeddings.embed_query(user_code_semantics)
        user_code_variables_vec = {}
        user_code_functions_vec = {}

        for key in user_code_variables.keys():
            variable_summary = user_code_variables[key]
            user_code_variables_vec[key] = {"raw":variable_summary, "vec": self.embeddings.embed_query(variable_summary)}
        
        for key in user_code_functions.keys():
            function_summary = user_code_functions[key]
            user_code_functions_vec[key] = {"raw":function_summary, "vec": self.embeddings.embed_query(function_summary)}        

        best_match = None
        best_score = 0
        best_semantic_cosine_score = 0
        best_semantic_jaccard_score = 0
        best_total_var_score = 0
        best_total_func_score = 0

    
        for rag_entry_id, rag_entry in self.rag_entries.items():

            # Semantic-Analysis Scores
            rag_entry_code_semantics_emded = rag_entry.code_semantics["vec"]
            semantic_cosine_score = self.compute_cosine_similarity(user_code_semantics_emded, rag_entry_code_semantics_emded)

            rag_entry_code_semantics_keywords = set(rag_entry.code_semantics["ner"])
            semantic_jaccard_score = self.compute_jaccard_similarity_fuzz(user_code_semantics_keywords, rag_entry_code_semantics_keywords)

            # Taint-Analysis Scores
            verification_var_mapping = self.find_var_func_mapping(user_code_variables_vec, rag_entry.vulnerability_related_variables)
            verification_func_mapping = self.find_var_func_mapping(user_code_functions_vec, rag_entry.vulnerability_related_functions)

            total_var_score = 0
            if len(verification_var_mapping) > 0:
                for rag_entry_var_name, match_result in verification_var_mapping.items():
                    total_var_score += match_result["score"] # cosine similarity score
                total_var_score /= len(verification_var_mapping)

            total_func_score = 0
            if len(verification_func_mapping) > 0:
                for rag_entry_func_name, match_result in verification_func_mapping.items():
                    total_func_score += match_result["score"] # cosine similarity score
                total_func_score /= (len(verification_func_mapping))


            # Total Score
            # [58.7924, 35.4870, 51.2777,  8.0147]
            # semantic_cosine_score, semantic_jaccard_score, total_var_score, total_func_score
            combined_score = 58.7924 * semantic_cosine_score + 35.4870 * semantic_jaccard_score + 51.2777 * total_var_score + 8.0147 * total_func_score

            if combined_score > best_score:
                best_semantic_cosine_score = semantic_cosine_score
                best_semantic_jaccard_score = semantic_jaccard_score
                best_total_var_score = total_func_score
                best_total_func_score = total_func_score
                best_score = combined_score
                best_match = rag_entry_id
        
        # Return Rag Entry and Mappings
        best_match_rag_entry = self.rag_entries[best_match]
        verification_var_mapping = self.find_var_func_mapping(user_code_variables_vec, best_match_rag_entry.vulnerability_related_variables)
        verification_func_mapping = self.find_var_func_mapping(user_code_functions_vec, best_match_rag_entry.vulnerability_related_functions)

        # print(best_score, best_semantic_cosine_score, best_semantic_jaccard_score, best_total_var_score, best_total_func_score)
        return best_match_rag_entry, verification_var_mapping, verification_func_mapping, list(user_code_semantics_keywords), best_score, best_semantic_jaccard_score

    def normalize_cosine_score(self,score):
        return (score+1)/2

    def calc_vec(self, var_or_func_dict):
        var_or_func_vec = {}
        for key in var_or_func_dict.keys():
            variable_summary = var_or_func_dict[key]
            var_or_func_vec[key] = {"raw":variable_summary, "vec": self.embeddings.embed_query(variable_summary)}   

        return var_or_func_vec     

    # Search for the matching rag entry
    def search_all(self,  user_code_semantics_keywords,user_code_semantics_emded: str, user_code_variables_vec: dict, user_code_functions_vec: dict):
        results= {}
    
        for rag_entry_id, rag_entry in self.rag_entries.items():

            # Semantic-Analysis Scores
            rag_entry_code_semantics_emded = rag_entry.code_semantics["vec"]
            semantic_cosine_score = self.compute_cosine_similarity(user_code_semantics_emded, rag_entry_code_semantics_emded)

            rag_entry_code_semantics_keywords = set(rag_entry.code_semantics["ner"])
            semantic_jaccard_score = self.compute_jaccard_similarity_fuzz(user_code_semantics_keywords, rag_entry_code_semantics_keywords)

            # Taint-Analysis Scores
            verification_var_mapping = self.find_var_func_mapping(user_code_variables_vec, rag_entry.vulnerability_related_variables)
            verification_func_mapping = self.find_var_func_mapping(user_code_functions_vec, rag_entry.vulnerability_related_functions)

            total_var_score = 0
            if len(verification_var_mapping) > 0:
                for rag_entry_var_name, match_result in verification_var_mapping.items():
                    total_var_score += match_result["score"] # cosine similarity score
                total_var_score /= len(verification_var_mapping)

            total_func_score = 0
            if len(verification_func_mapping) > 0:
                for rag_entry_func_name, match_result in verification_func_mapping.items():
                    total_func_score += match_result["score"] # cosine similarity score
                total_func_score /= (len(verification_func_mapping))

            results[rag_entry.cve_id+"_"+rag_entry.function_name] = [semantic_cosine_score, semantic_jaccard_score, total_var_score, total_func_score]
        
        return results

    def get(self, rag_entry_id):
        return self.rag_entries[rag_entry_id]