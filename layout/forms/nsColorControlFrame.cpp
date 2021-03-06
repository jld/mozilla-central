/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nsColorControlFrame.h"

#include "nsContentCreatorFunctions.h"
#include "nsContentList.h"
#include "nsContentUtils.h"
#include "nsFormControlFrame.h"
#include "nsGkAtoms.h"
#include "nsIDOMHTMLInputElement.h"
#include "nsIDOMNode.h"
#include "nsStyleSet.h"

nsColorControlFrame::nsColorControlFrame(nsStyleContext* aContext):
  nsColorControlFrameSuper(aContext)
{
}

nsIFrame*
NS_NewColorControlFrame(nsIPresShell* aPresShell, nsStyleContext* aContext)
{
  return new (aPresShell) nsColorControlFrame(aContext);
}

NS_IMPL_FRAMEARENA_HELPERS(nsColorControlFrame)

NS_QUERYFRAME_HEAD(nsColorControlFrame)
  NS_QUERYFRAME_ENTRY(nsIAnonymousContentCreator)
NS_QUERYFRAME_TAIL_INHERITING(nsColorControlFrameSuper)


void nsColorControlFrame::DestroyFrom(nsIFrame* aDestructRoot)
{
  nsFormControlFrame::RegUnRegAccessKey(static_cast<nsIFrame*>(this), false);
  nsContentUtils::DestroyAnonymousContent(&mColorContent);
  nsColorControlFrameSuper::DestroyFrom(aDestructRoot);
}

nsIAtom*
nsColorControlFrame::GetType() const
{
  return nsGkAtoms::colorControlFrame;
}

#ifdef DEBUG
NS_IMETHODIMP
nsColorControlFrame::GetFrameName(nsAString& aResult) const
{
  return MakeFrameName(NS_LITERAL_STRING("ColorControl"), aResult);
}
#endif

// Create the color area for the button.
// The frame will be generated by the frame constructor.
nsresult
nsColorControlFrame::CreateAnonymousContent(nsTArray<ContentInfo>& aElements)
{
  nsCOMPtr<nsIDocument> doc = mContent->GetCurrentDoc();
  nsCOMPtr<nsINodeInfo> nodeInfo =
      doc->NodeInfoManager()->GetNodeInfo(nsGkAtoms::div, nullptr,
        kNameSpaceID_XHTML,
        nsIDOMNode::ELEMENT_NODE);

  nsresult rv = NS_NewHTMLElement(getter_AddRefs(mColorContent),
                                  nodeInfo.forget(),
                                  mozilla::dom::NOT_FROM_PARSER);
  NS_ENSURE_SUCCESS(rv, rv);

  // Mark the element to be native anonymous before setting any attributes.
  mColorContent->SetIsNativeAnonymousRoot();

  rv = UpdateColor();
  NS_ENSURE_SUCCESS(rv, rv);

  nsCSSPseudoElements::Type pseudoType = nsCSSPseudoElements::ePseudo_mozColorSwatch;
  nsRefPtr<nsStyleContext> newStyleContext = PresContext()->StyleSet()->
    ResolvePseudoElementStyle(mContent->AsElement(), pseudoType,
                              StyleContext(), mColorContent->AsElement());
  if (!aElements.AppendElement(ContentInfo(mColorContent, newStyleContext))) {
    return NS_ERROR_OUT_OF_MEMORY;
  }

  return NS_OK;
}

void
nsColorControlFrame::AppendAnonymousContentTo(nsBaseContentList& aElements,
                                              uint32_t aFilter)
{
  aElements.MaybeAppendElement(mColorContent);
}

nsresult
nsColorControlFrame::UpdateColor()
{
  // Get the color from the "value" property of our content; it will return the
  // default color (through the sanitization algorithm) if there is none.
  nsAutoString color;
  nsCOMPtr<nsIDOMHTMLInputElement> elt = do_QueryInterface(mContent);
  elt->GetValue(color);
  MOZ_ASSERT(!color.IsEmpty(),
             "Content node's GetValue() should return a valid color string "
             "(the default color, in case no valid color is set)");

  // Set the background-color style property of the swatch element to this color
  return mColorContent->SetAttr(kNameSpaceID_None, nsGkAtoms::style,
      NS_LITERAL_STRING("background-color:") + color, true);
}

NS_IMETHODIMP
nsColorControlFrame::AttributeChanged(int32_t  aNameSpaceID,
                                      nsIAtom* aAttribute,
                                      int32_t  aModType)
{
  NS_ASSERTION(mColorContent, "The color div must exist");

  // If the value attribute is set, update the color box
  if (aNameSpaceID == kNameSpaceID_None && nsGkAtoms::value == aAttribute) {
    UpdateColor();
  }
  return nsColorControlFrameSuper::AttributeChanged(aNameSpaceID, aAttribute,
                                                    aModType);
}

nsIFrame*
nsColorControlFrame::GetContentInsertionFrame()
{
  return this;
}
