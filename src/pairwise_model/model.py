import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
import random
import json
import argparse
import os


def load_json(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


# ======= Dummy Similarity Data ========
similarities = {
}

labels = {
}

# ======= Dataset ========
class CVEMatchDataset(Dataset):
    def __init__(self, similarities, labels, num_negatives=5):
        self.samples = []
        for snippet_id in similarities.keys():
            cve_scores = similarities[snippet_id]
            pos_cves = labels[snippet_id]
            pos_feats = [torch.tensor(cve_scores[c], dtype=torch.float) for c in pos_cves if c in cve_scores]

            # Sample negatives (not in positives)
            neg_cves = [cid for cid in cve_scores if cid not in pos_cves]
            neg_cves = random.sample(neg_cves, min(num_negatives, len(neg_cves)))
            neg_feats = [torch.tensor(cve_scores[c], dtype=torch.float) for c in neg_cves]

            self.samples.append((pos_feats, neg_feats))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        return self.samples[idx]  # returns list of pos_feats and list of neg_feats
# ======= Model ========
class SimilarityScorer(nn.Module):
    def __init__(self):
        super().__init__()
        self.linear = nn.Linear(4, 1, bias=False)  # 4 input similarity features
        self.linear.weight.data = torch.tensor([[0.2, 0.2, 0.3, 0.3]])  # shape (1, 4)

    def forward(self, x):
        # weight = self.linear.weight
        # normalized_weight = weight / weight.sum(dim=1, keepdim=True)
        # out = F.linear(x, normalized_weight, self.linear.bias)
        # return out.squeeze(-1)
        return self.linear(x).squeeze(-1)

# ======= Loss ========
def pairwise_ranking_loss(score_pos, score_negs, margin=1.0):
    # print(score_pos)
    # print(score_pos.unsqueeze(1))
    # print(score_negs)
    # print(score_negs.size())
    # print(score_pos.unsqueeze(1) - score_negs)
    return F.relu(margin - (score_pos.unsqueeze(1) - score_negs)).mean()

# ======= Training ========
def train_model(train_snippet_ids, max_epoch=200,save_path="cve_scorer_weights.pt"):

    train_similarities = {}
    train_labels = {}

    for snippet_id in train_snippet_ids:
        train_similarities[snippet_id] = similarities[snippet_id]
        train_labels[snippet_id] = labels[snippet_id]


    dataset = CVEMatchDataset(train_similarities, train_labels, num_negatives=10)
    dataloader = DataLoader(dataset, batch_size=12, shuffle=True)

    model = SimilarityScorer()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.005)


    for epoch in range(max_epoch):
        total_loss = 0
        for pos_feats, neg_feats in dataloader:
            all_pos = []
            all_neg = []
            for i in range(len(pos_feats)):
                for pos in pos_feats[i]:
                    all_pos.append(pos)
            for i in range(len(neg_feats)):
                for neg in neg_feats[i]:
                    all_neg.append(neg)

            pos_tensor = torch.stack(all_pos).float()  # shape (N, 4)
            neg_tensor = torch.stack(all_neg).float()  # shape (N, 4)

            score_pos = model(pos_tensor)
            score_neg = model(neg_tensor)

            loss = pairwise_ranking_loss(score_pos, score_neg, margin=5.0)
    
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        
        print(f"Epoch {epoch+1}: Loss = {total_loss:.4f}")

    print("✅ Training complete. Saving model...")
    torch.save(model.state_dict(), save_path)
    print("Model saved to:", save_path)
    return model

# ======= Loading Model for Inference ========
def load_model(path="cve_scorer_weights.pt"):
    model = SimilarityScorer()
    model.load_state_dict(torch.load(path))
    model.eval()
    return model


single_match = True
def load_data():
    root_dirs = ['CVE-list']
    cve_to_all_cves_map = {}

    for root_dir in root_dirs:
        for cve_dir in os.listdir(root_dir):

            if cve_dir == "BACKUP" or cve_dir == "EMPTY_CVE":
                continue

            cve_path = os.path.join(root_dir, cve_dir)
            code_dir = os.path.join(cve_path, "out_v2", "code")
            cve_pairwise_data_path = os.path.join(cve_path, "out_v2", "pairwise_data.json")
            cve_pairwise_data = load_json(cve_pairwise_data_path)
            similarities.update(cve_pairwise_data)


            db_entry_path = os.path.join(cve_path, "out_v2", "db_entry.json")
            db_entry_data = load_json(db_entry_path)

            # for single match
            if single_match:
                for code_file in os.listdir(code_dir):
                    if not code_file.endswith(".json"):
                        continue

                    code_file_path =  os.path.join(cve_path, "out_v2", "code", code_file)
                    if load_json(code_file_path)["is_vulnerable"] == "N/A":
                        continue
                    
                    if single_match:
                        key = code_file_path
                        value = db_entry_data["cve_id"] + "_" + db_entry_data["function_name"]
                        labels[key] = [value]

def predict_best_cve(model, query_similarities):
    model.eval()
    best_score = float('-inf')
    best_cve = None

    for cve_id, sim_vector in query_similarities.items():
        features = torch.tensor(sim_vector, dtype=torch.float).unsqueeze(0)  # shape: (1, 4)
        with torch.no_grad():
            score = model(features).item()
        if score > best_score:
            best_score = score
            best_cve = cve_id

    return best_cve, best_score


def validate_model(model, validation_snippet_ids, top_k=3):
    model.eval()
    top1_correct = 0
    topk_correct = 0
    relaxed_correct = 0
    total = 0

    for snippet_id in validation_snippet_ids:
        if snippet_id not in similarities or snippet_id not in labels:
            continue

        cve_scores = similarities[snippet_id]
        correct_cves = labels[snippet_id]
    
        # Compute scores for all CVEs
        cve_ids = list(cve_scores.keys())
        sim_vectors = torch.tensor([cve_scores[cid] for cid in cve_ids], dtype=torch.float)
        # print(sim_vectors[0])

        with torch.no_grad():
            scores = model(sim_vectors).tolist()

        # Rank by score descending
        ranked = sorted(zip(cve_ids, scores), key=lambda x: x[1], reverse=True)
        ranked_cves = [cid for cid, _ in ranked]

        total += 1
        if ranked_cves[0] in correct_cves:
            top1_correct += 1

        if ranked_cves[0].split('_')[0] == correct_cves[0].split('_')[0]:
            relaxed_correct += 1

        if any(c in ranked_cves[:top_k] for c in correct_cves):
            topk_correct += 1

    if total == 0:
        print("No validation samples found.")
        return

    print(total, )
    print(f"Top-1 Accuracy: {top1_correct / total:.4f}")
    print(f"Relaxed Accuracy: {relaxed_correct / total:.4f}")
    print(f"Top-{top_k} Accuracy: {topk_correct / total:.4f}")

# ======= Example Usage ========

if __name__ == "__main__":

    load_data()


    parser = argparse.ArgumentParser()
    parser.add_argument("-te", "--test", dest="for_test", action="store_true")
    parser.add_argument("-tr", "--train", dest="for_train", action="store_true")
    parser.add_argument("-ld", "--load", dest="for_load", action="store_true")
    args = parser.parse_args()

    if args.for_test:
        # 1. Get all snippet IDs
        all_snippets = list(similarities.keys())

        # 2. Shuffle
        random.shuffle(all_snippets)

        # 3. Split (e.g., 85% train, 15% test) (15% for validation)
        split_ratio = 0.85
        split_index = int(len(all_snippets) * split_ratio)

        train_snippet_ids = all_snippets[:split_index]
        validation_snippet_ids = all_snippets[split_index:]

        model = train_model(train_snippet_ids, max_epoch=500)
        validate_model(model, validation_snippet_ids)
    elif args.for_train:
        train_snippet_ids =  list(similarities.keys())
        model = train_model(train_snippet_ids, max_epoch=500)
        validate_model(model, train_snippet_ids)
        
    elif args.for_load:
        # 1. Get all snippet IDs
        all_snippets = list(similarities.keys())

        # 2. Shuffle
        random.shuffle(all_snippets)

        # 3. Split (e.g., 85% train, 15% test) (15% for validation)
        split_ratio = 0.85
        split_index = int(len(all_snippets) * split_ratio)

        train_snippet_ids = all_snippets[:split_index]
        validation_snippet_ids = all_snippets[split_index:]

        model = load_model()
        print(model.linear.weight)
        validate_model(model, validation_snippet_ids)
