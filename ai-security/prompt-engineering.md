# AI Prompt Engineering Cheatsheet

| Technique | Description | Example | When to Use |
|-----------|-------------|---------|------------|
| **Be Specific** | Use clear, precise language | "Generate a 5-point marketing plan for an eco-friendly water bottle" vs "Give me marketing ideas" | When you need focused, relevant outputs |
| **Use Examples** | Provide samples of desired output | "Rewrite this in a professional tone: 'Hey dude, got your email'" | To guide the model's style/format |
| **Chain of Thought** | Break complex problems into steps | "First, identify the variables in this equation. Then solve for x." | For logical/mathematical problems |
| **Role Prompting** | Assign a role to the AI | "As an experienced cybersecurity analyst, review these firewall logs" | When domain expertise is needed |
| **Few-Shot Learning** | Provide several examples before the main task | "Example 1: [input→output], Example 2: [input→output]. Now do: [new input]" | For establishing patterns |
| **System Instructions** | Set overall behavior guidelines | "You are a helpful assistant who specializes in summarizing medical research" | To establish consistent behavior |
| **Temperature Control** | Adjust creativity vs precision | (Temperature 0.2: precise, 0.8: creative) | Low for factual/code, high for creative |
| **Format Specification** | Request specific output format | "Respond in a JSON object with keys for 'analysis' and 'recommendation'" | For structured data or parsing |
| **Constraints** | Set limitations | "Explain quantum computing in under 100 words using only 5th-grade vocabulary" | To control scope/complexity |
| **Iteration** | Refine outputs in steps | "Take this draft and improve its structure while keeping the content intact" | For progressive refinement |
| **Context Loading** | Provide relevant background | "Here's my previous code: [code]. Help me debug the error in line 27" | When prior information matters |
| **Persona Specification** | Define audience or perspective | "Explain blockchain for a finance professional" | To tailor explanations appropriately |
| **Metaphors & Analogies** | Request explanations using comparisons | "Explain HTTPS using a postal mail analogy" | For simplifying complex concepts |
| **Emotional Tone** | Specify desired emotional quality | "Write an encouraging email declining a job candidate" | To control the emotional impact |
| **Anti-Prompt** | Specify what to avoid | "Explain SEO without using technical jargon" | To prevent unwanted content |

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Too verbose | "Be concise. Limit your response to 3 sentences." |
| Too generic | "Provide specific, actionable examples that apply to my case." |
| Hallucinations | "Only include verifiable information. If uncertain, acknowledge limitations." |
| Repetitive answers | "Give me diverse approaches. Each point should cover a different aspect." |
| Technical jargon | "Explain as if I'm a beginner with no technical background." |
| Lack of structure | "Format your response with numbered points and subheadings." |
